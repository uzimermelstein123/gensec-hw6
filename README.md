# Page Network Inspector

Loads a page in headless Chromium and reports every network request it makes.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium   # one-time ~150 MB download
```

## Usage

```bash
python app.py https://www.espn.com
python app.py https://www.nba.com --json
```

The report shows total requests and bytes, requests by resource type, the top 10
hosts (IP, port, request count), a first-party vs third-party split, and flags for
plain-HTTP requests and non-80/443 ports.
