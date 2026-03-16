# Contributing to Sentinel

## Setup
```bash
git clone https://github.com/timmeck/sentinel.git
cd sentinel
pip install -r requirements.txt
pip install pytest pytest-asyncio
pytest tests/ -v
```

## Adding a New Security Check
1. Add check function in `src/scanner/checks.py` or create a new module
2. Register it in `src/scanner/engine.py` `SCAN_PROFILES`
3. Add tests in `tests/`

## Code Style
- Pure Python, async everywhere
- Each check returns `list[dict]` with: category, severity, title, description, recommendation
