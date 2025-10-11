# DIRSEARCH by Raymond7
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)]

> Fast async directory & file brute-force scanner — CLI style for Linux terminals

## Overview
`path-scanner` adalah tool Python CLI interaktif untuk menemukan direktori/file tersembunyi dengan cepat menggunakan `aiohttp`. Dirancang ringan, cepat, dan praktis untuk penggunaan di terminal Linux.

## Features
- Asynchronous scanning (aiohttp)
- Realtime `Found > URL` (cyan in terminal)
- Baseline 404 probe (kurangi false-positive custom-404)
- Simpel: Single target & Mass scan modes
- Outputs: per-target `.json` & `.txt` (only found), plus aggregated `results.txt` with separators

## Install & Run
```bash
- git clone https://github.com/youruser/path-scanner.git
- cd path-scanner
- pip install aiohttp tqdm requests

- python scanner.py
# pilih:
# 1) Single target
# 2) Mass scanner (file of URLs)
