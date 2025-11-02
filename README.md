<div align="center">

# ?????? <span style="color: #4facfe;">ANON</span><span style="color: #00f2fe;">KH</span> Username OSINT

[![Python](https://img.shields.io/badge/Python-3.9+-yellow?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-blue?logo=open-source-initiative&logoColor=white)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v5.0-orange?logo=github&logoColor=white)](https://github.com/yourusername/HiddenEyes/releases)
[![Stars](https://img.shields.io/github/stars/yourusername/HiddenEyes?color=purple&logo=github&logoColor=white)](https://github.com/yourusername/HiddenEyes/stargazers)

</div>

Reliable, scriptable username reconnaissance across 30+ platforms with smart retries, filtering, and export support.

## ? What's New

- Configurable platform catalog via JSON or command-line filters.
- Smarter networking: retry/backoff with `urllib3`, randomised delays, rate limit detection.
- Richer results: response timings, Markdown/CSV/JSON exports, detailed summaries.
- Improved UX: colour-aware output, banner toggle, site listing, optional error report.

## ??? Installation

```bash
git clone https://github.com/angkerith1/username-osint.git
cd username-osint
python -m venv .venv && source .venv/bin/activate  # optional but recommended
pip install -r requirements.txt
```

## ?? Usage

```bash
python osint.py <username>
```

Helpful flags:

- `--list-sites` ? show bundled platforms and exit.
- `--include-category social --include-category gaming` ? scan only certain categories.
- `--exclude-site reddit --exclude-site twitter` ? skip specific platforms by name.
- `--sites-file custom_sites.json` ? load your own site catalog (see schema below).
- `--export csv --export-dir reports/` ? save a timestamped CSV report.
- `--no-banner` ? disable the ASCII banner for log pipelines.
- `--show-errors` ? print captured network/parsing issues at the end.

### Filter Examples

```bash
# Focus on professional networks
python osint.py alice --include-category professional --include-category tech

# Run quietly against a curated list
python osint.py bob --sites-file ./data/sites.min.json --no-banner --show-errors
```

## ?? Custom Site Definitions

Provide a JSON array where each object matches the internal structure:

```json
[
  {
    "name": "Product Hunt",
    "url": "https://www.producthunt.com/@{}",
    "method": "status",
    "expect": 404,
    "category": "startup"
  },
  {
    "name": "Example Forum",
    "url": "https://forum.example.com/u/{}",
    "method": "pattern",
    "pattern": "does not exist",
    "category": "community"
  }
]
```

Supported detection methods:

- `status`: treat matching `expect` status codes (int or list) as **not found**.
- `pattern`: treat the case-insensitive presence of `pattern` in the body as **not found**.

## ?? Development

- Lint: `pylint osint.py`
- Tests (when available): `pytest`
- Dry run without colours: `TERM=dumb python osint.py --no-banner --list-sites`

## ?? Legal & Ethical Use

This tool is provided for defensive research and account discovery with consent. Always follow local laws, regulations, and platform terms of service.
