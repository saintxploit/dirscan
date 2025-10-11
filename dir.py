#!/usr/bin/env python3
#coded by Raymond7
#scan like a real penguin
"""
scanner.py - Interactive CLI path scanner

Features:
 - Interactive menu (Single target / Mass scanner)
 - Realtime "Found > ..." notifications in cyan
 - Save only confirmed found results (status int < 400 and not matching baseline 404)
 - Aggregated results.txt with separators between targets
 - Baseline 404 signature probe using body length + sha256 to reduce false positives

Dependencies:
 pip install aiohttp tqdm requests

Permissions: Only scan systems you have permission to test.
"""

import os
import sys
import asyncio
import aiohttp
import time
import csv
import json
import random
import string
import hashlib
from urllib.parse import urljoin, urlparse
from tqdm import tqdm
from typing import List, Optional, Set
import requests

# ---------------- Banner -----------------
BANNER = r'''
  ____  ___  ____  ____  ____  ____  ____  ____
 |  _ \|_ _|/ ___||  _ \|  _ \|  _ \|  _ \|  _ \
 | | | || || |  _ | | | | | | | | | | | | | | |
 | |_| |__   _| |_| || |_| | |_| | |_| | |_| | |
 |____/   |_|  \____||____/|____/|____/|____/|_|

                Dirsearch by Raymond7
'''

def print_banner():
    try:
        print(BANNER)
    except Exception:
        pass

# ---------- Robots helpers ----------

def fetch_robots(base_url: str, timeout: int = 8) -> Optional[str]:
    robots_url = urljoin(base_url.rstrip('/') + '/', 'robots.txt')
    try:
        resp = requests.get(robots_url, timeout=timeout, headers={"User-Agent": "Dirsearch-RobotsChecker/1.0"})
        if resp.status_code == 200:
            return resp.text
        else:
            return None
    except requests.RequestException:
        return None

def parse_robots(robots_txt: str) -> Set[str]:
    disallows = set()
    current_user_agents = []
    for line in robots_txt.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':', 1)
        if len(parts) != 2:
            continue
        key = parts[0].strip().lower()
        val = parts[1].strip()
        if key == 'user-agent':
            current_user_agents = [ua.strip() for ua in val.split(',')]
        elif key == 'disallow':
            if not current_user_agents or '*' in current_user_agents:
                if val:
                    disallows.add(val.rstrip('/'))
    return disallows

def filter_paths_by_robots(paths: List[str], disallows: Set[str]) -> List[str]:
    if not disallows:
        return paths
    filtered = []
    for p in paths:
        normalized = '/' + p.lstrip('/')
        skip = False
        for d in disallows:
            if d == '':
                continue
            if normalized.startswith(d if d.startswith('/') else '/' + d):
                skip = True
                break
        if not skip:
            filtered.append(p)
    return filtered

# ---------- Async worker ----------
async def fetch_async(session: aiohttp.ClientSession,
                      method: str,
                      url: str,
                      sem: asyncio.Semaphore,
                      timeout: int,
                      allow_redirects: bool,
                      sleep_between: float) -> dict:
    """
    Performs an async HTTP request and returns a dict containing:
      - url, status (int or str), reason, length (int or None), sha256 (hex or None), final_url
    """
    async with sem:
        try:
            async with session.request(method, url, timeout=timeout, allow_redirects=allow_redirects) as resp:
                body_bytes = b""
                try:
                    body_bytes = await resp.read()
                except Exception:
                    body_bytes = b""
                text_len = len(body_bytes) if body_bytes is not None else None
                sha = hashlib.sha256(body_bytes).hexdigest() if body_bytes is not None else None
                result = {
                    "url": url,
                    "status": resp.status,
                    "reason": str(resp.reason) if hasattr(resp, 'reason') else None,
                    "length": text_len,
                    "sha256": sha,
                    "final_url": str(resp.url)
                }
                if sleep_between:
                    await asyncio.sleep(sleep_between)
                return result
        except asyncio.TimeoutError:
            return {"url": url, "status": "timeout", "reason": "timeout", "length": None, "sha256": None, "final_url": None}
        except aiohttp.ClientError as e:
            return {"url": url, "status": "error", "reason": repr(e), "length": None, "sha256": None, "final_url": None}
        except Exception as e:
            return {"url": url, "status": "error", "reason": repr(e), "length": None, "sha256": None, "final_url": None}

# ---------- Fallback synchronous worker (requests) ----------
def fetch_sync_requests(method: str, url: str, timeout: int, allow_redirects: bool, headers: dict) -> dict:
    try:
        if method.upper() == 'HEAD':
            resp = requests.head(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)
            if resp.status_code == 405:
                resp = requests.get(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)
        else:
            resp = requests.get(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)
        body = resp.text if resp.text is not None else ""
        b_bytes = body.encode('utf-8', errors='ignore') if body is not None else b""
        text_len = len(b_bytes)
        sha = hashlib.sha256(b_bytes).hexdigest() if b_bytes is not None else None
        return {"url": url, "status": resp.status_code, "reason": resp.reason, "length": text_len, "sha256": sha, "final_url": resp.url}
    except requests.Timeout:
        return {"url": url, "status": "timeout", "reason": "timeout", "length": None, "sha256": None, "final_url": None}
    except requests.RequestException as e:
        return {"url": url, "status": "error", "reason": repr(e), "length": None, "sha256": None, "final_url": None}

# ---------- Baseline 404 probe ----------
def get_404_signature(base_url: str, method: str = "GET", headers: Optional[dict] = None, timeout: int = 8) -> Optional[dict]:
    """
    Probe a highly-likely-nonexistent path to obtain baseline signature:
      returns {'length': int, 'sha256': str, 'status': int} or None on failure.
    """
    if headers is None:
        headers = {"User-Agent": "PathScanner-404-Probe/1.0"}
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=24))
    probe_path = "/this-path-should-not-exist-" + rand + ".txt"
    probe_url = urljoin(base_url.rstrip('/') + '/', probe_path.lstrip('/'))
    try:
        resp = requests.get(probe_url, timeout=timeout, headers=headers, allow_redirects=True)
        body = resp.text or ""
        b_bytes = body.encode('utf-8', errors='ignore')
        return {"length": len(b_bytes), "sha256": hashlib.sha256(b_bytes).hexdigest(), "status": resp.status_code}
    except requests.RequestException:
        return None

def is_same_signature(res: dict, baseline: Optional[dict]) -> bool:
    """
    Compare response vs baseline. Return True if likely same (i.e., custom 404).
    Strategy:
      - If baseline is None -> return False (can't compare).
      - If both sha256 present and equal -> True.
      - Else if both lengths present and equal -> True.
      - Else -> False.
    """
    if not baseline:
        return False
    try:
        bl_sha = baseline.get('sha256')
        bl_len = baseline.get('length')
        if bl_sha and res.get('sha256') and bl_sha == res.get('sha256'):
            return True
        if bl_len is not None and res.get('length') is not None and bl_len == res.get('length'):
            return True
    except Exception:
        pass
    return False

# ---------- Orchestrator (uses baseline to reduce false positives) ----------
async def run_scanner(base_url: str,
                      paths: List[str],
                      concurrency: int = 20,
                      timeout: int = 10,
                      method: str = "GET",
                      headers: Optional[dict] = None,
                      allow_redirects: bool = False,
                      proxy: Optional[str] = None,
                      sleep_between: float = 0.0,
                      show_only: Optional[List[int]] = None) -> List[dict]:
    """
    Run the async scanner. Returns only 'found' results by default (status int < 400)
    and excludes responses matching the baseline 404 signature when possible.
    """
    if headers is None:
        headers = {"User-Agent": "PathScanner/1.0 (+https://example)"}

    # Get baseline synchronously (quick)
    baseline = None
    try:
        baseline = get_404_signature(base_url, method=method, headers=headers, timeout=timeout)
        if baseline:
            tqdm.write(f"[info] Learned baseline: status={baseline.get('status')}, length={baseline.get('length')}")
        else:
            tqdm.write("[info] Baseline probe failed or unavailable; proceeding without baseline filtering.")
    except Exception:
        baseline = None

    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=0)
    timeout_obj = aiohttp.ClientTimeout(total=None, sock_connect=timeout, sock_read=timeout)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj, headers=headers) as session:
        tasks = []
        results = []

        for p in paths:
            target = urljoin(base_url.rstrip('/') + '/', p.lstrip('/'))
            tasks.append(fetch_async(session, method, target, sem, timeout, allow_redirects, sleep_between))

        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning"):
            res = await coro
            try:
                status_val = res.get('status')
                is_int_status = isinstance(status_val, int)
                tentatively_found = is_int_status and status_val < 400

                # If baseline exists and we have length/sha, compare
                if tentatively_found and baseline:
                    if is_same_signature(res, baseline):
                        # likely custom-404 -> skip
                        tqdm.write(f"[info] Skipping likely-404 -> {res.get('url')}")
                        tentatively_found = False

                # Realtime output for confirmed found
                if tentatively_found:
                    tqdm.write(f"\033[96mFound > {res.get('url')}\033[0m")  # cyan

                # Decide to append
                if show_only:
                    if is_int_status and status_val in show_only:
                        results.append(res)
                else:
                    if tentatively_found:
                        results.append(res)
            except Exception:
                pass
        return results

# ---------- Helpers for saving ----------
def save_results_csv(results: List[dict], filename: str):
    keys = ["url", "status", "reason", "length", "sha256", "final_url"]
    with open(filename, "w", newline='', encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k) for k in keys})

def save_results_json(results: List[dict], filename: str):
    with open(filename, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2, ensure_ascii=False)

def save_results_txt(results: List[dict], filename: str, target_name: Optional[str] = None, append: bool = True):
    """
    Append or write found results to a plain .txt file.
    If target_name provided, write a separator header.
    """
    mode = 'a' if append else 'w'
    with open(filename, mode, encoding='utf-8') as f:
        if target_name:
            f.write("\n" + "="*60 + "\n")
            f.write(f"Target: {target_name}\n")
            f.write("="*60 + "\n")
        for r in results:
            status = r.get('status')
            url = r.get('url')
            f.write(f"{status} {url}\n")

# ---------- Interactive menu helpers ----------
def prompt_paths_wordlist(default='common_paths.txt') -> List[str]:
    while True:
        wl = input(f"Enter paths wordlist path (press Enter to use ./{default}): ").strip()
        if not wl:
            wl = default
        if os.path.isfile(wl):
            return load_wordlist(wl)
        else:
            print(f"File not found: {wl}")

def prompt_target_url() -> str:
    url = input("Enter target base URL (e.g. https://example.com): ").strip()
    if not url:
        print("No URL entered. Returning to menu.")
        return ''
    if not urlparse(url).scheme:
        url = 'http://' + url
    return url

def prompt_targets_file() -> List[str]:
    while True:
        path = input("Enter targets file path (one URL per line): ").strip()
        if not path:
            print("No file entered. Returning to menu.")
            return []
        if os.path.isfile(path):
            lines = []
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    s = line.strip()
                    if s:
                        if not urlparse(s).scheme:
                            s = 'http://' + s
                        lines.append(s)
            return lines
        else:
            print(f"File not found: {path}")

def load_wordlist(path: str) -> List[str]:
    entries = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            entries.append(s)
    return entries

# ---------- Flow: single target ----------
def run_single_target_flow():
    url = prompt_target_url()
    if not url:
        return
    paths = prompt_paths_wordlist()
    respect_robots = input("Respect robots.txt? [Y/n]: ").strip().lower()
    respect = True if respect_robots in ('', 'y', 'yes') else False

    if respect:
        robots = fetch_robots(url)
        if robots:
            dis = parse_robots(robots)
            print(f"Applying {len(dis)} robots disallow rules to paths wordlist.")
            paths = filter_paths_by_robots(paths, dis)

    concurrency = input("Concurrency (default 30): ").strip()
    try:
        concurrency = int(concurrency) if concurrency else 30
    except ValueError:
        concurrency = 30
    timeout = input("Timeout seconds (default 10): ").strip()
    try:
        timeout = int(timeout) if timeout else 10
    except ValueError:
        timeout = 10

    method = input("HTTP method [GET/HEAD] (default GET): ").strip().upper() or 'GET'
    if method not in ('GET', 'HEAD'):
        method = 'GET'

    print(f"Starting scan of {url} with {len(paths)} paths (concurrency {concurrency})...")
    headers = {"User-Agent": "PathScanner/1.0 (+https://example)"}
    show_only_input = input("Show only status codes (comma-separated), or press Enter to keep only found (<400): ").strip()
    show_only = None
    if show_only_input:
        try:
            show_only = [int(x.strip()) for x in show_only_input.split(',') if x.strip()]
        except ValueError:
            show_only = None

    t0 = time.time()
    results = asyncio.run(run_scanner(url, paths, concurrency=concurrency, timeout=timeout, method=method, headers=headers, show_only=show_only))
    dt = time.time() - t0
    print(f"\nScan finished in {dt:.2f}s — found results: {len(results)}")

    out_base = input("Output base filename (press Enter to use 'results'): ").strip() or 'results'
    # Save per-target JSON and TXT (found only)
    save_results_json(results, out_base + '.json')
    save_results_txt(results, out_base + '.txt', target_name=url, append=False)
    # Also append to global aggregated results.txt for convenience
    # Create aggregated results file if not exists
    if not os.path.isfile('results.txt'):
        try:
            with open('results.txt', 'w', encoding='utf-8') as f:
                f.write(f"Aggregated scan results - started: {time.ctime()}\n")
                f.write("="*60 + "\n")
        except Exception:
            pass
    save_results_txt(results, 'results.txt', target_name=url, append=True)
    print(f"Saved {out_base}.json and {out_base}.txt (found only). Also appended to results.txt")

# ---------- Flow: mass scanner ----------
def run_mass_scanner_flow():
    targets = prompt_targets_file()
    if not targets:
        return
    paths = prompt_paths_wordlist()
    respect_robots = input("Respect robots.txt per-target? [Y/n]: ").strip().lower()
    respect = True if respect_robots in ('', 'y', 'yes') else False

    concurrency = input("Per-target concurrency (default 20): ").strip()
    try:
        concurrency = int(concurrency) if concurrency else 20
    except ValueError:
        concurrency = 20
    timeout = input("Timeout seconds per request (default 8): ").strip()
    try:
        timeout = int(timeout) if timeout else 8
    except ValueError:
        timeout = 8
    method = input("HTTP method [GET/HEAD] (default HEAD to save bandwidth): ").strip().upper() or 'HEAD'
    if method not in ('GET', 'HEAD'):
        method = 'HEAD'

    headers = {"User-Agent": "PathScanner/1.0 (+https://example)"}

    # Ensure aggregated results.txt is started fresh for this mass scan
    try:
        with open('results.txt', 'w', encoding='utf-8') as f:
            f.write(f"Aggregated scan results - started: {time.ctime()}\n")
            f.write("="*60 + "\n")
    except Exception:
        pass

    # iterate targets sequentially (to avoid overloading)
    summary = []
    for t in targets:
        print(f"\n=== Scanning target: {t} ===")
        p_list = list(paths)
        if respect:
            robots = fetch_robots(t)
            if robots:
                dis = parse_robots(robots)
                p_list = filter_paths_by_robots(p_list, dis)
                print(f"Applied robots rules -> {len(p_list)} paths remain")
        try:
            results = asyncio.run(run_scanner(t, p_list, concurrency=concurrency, timeout=timeout, method=method, headers=headers))
        except Exception as e:
            print(f"Error scanning {t}: {e}")
            continue
        # save per-target results (found only)
        safe_host = urlparse(t).netloc.replace(':','_')
        outbase = f"{safe_host}_results"
        save_results_json(results, outbase + '.json')
        save_results_txt(results, outbase + '.txt', target_name=t, append=False)
        # aggregated txt: append with separator
        save_results_txt(results, 'results.txt', target_name=t, append=True)
        print(f"Saved {outbase}.json and {outbase}.txt. Appended found results to results.txt")
        # collect brief summary
        hits = [r for r in results if isinstance(r.get('status'), int) and r['status'] < 400]
        summary.append((t, len(p_list), len(hits)))

    print("\n=== Mass scan summary ===")
    for s in summary:
        print(f"{s[0]} -> scanned {s[1]} paths, hits: {s[2]}")

# ---------- Main menu ----------
def main_menu():
    print_banner()
    while True:
        print("\nMenu:")
        print("  1) Single target")
        print("  2) Mass scanner (file of target URLs)")
        print("  3) Exit")
        choice = input("Choose an option [1-3]: ").strip()
        if choice == '1':
            run_single_target_flow()
        elif choice == '2':
            run_mass_scanner_flow()
        elif choice == '3':
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)
