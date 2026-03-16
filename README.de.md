# Sentinel — AI Security Scanner

[English](README.md) | **Deutsch**

Self-hosted Security Scanner mit AI-Analyse. Scannt Web-Apps auf Schwachstellen — Headers, SSL, Ports, Cookies, SQL Injection, XSS, CORS, Directory Traversal, Rate Limiting, DNS und mehr. Generiert Berichte mit Severity-Ratings und Fix-Empfehlungen. Alles lokal mit Ollama.

**Reines Python + SQLite. 49 Tests. Keine API-Keys noetig.**

## Features

| Feature | Beschreibung |
|---|---|
| **16 Security Checks** | Headers, SSL, Ports, Cookies, Paths, Technology, HTTPS, SQLi, XSS, Open Redirect, Directory Traversal, Rate Limiting, CORS, DNS, API, Crawler |
| **Vulnerability Testing** | Aktives Probing fuer SQLi, XSS, Open Redirect, Directory Traversal |
| **AI Reports** | LLM-generierte Analyse mit Fix-Empfehlungen |
| **Scan Profiles** | quick (5), standard (10), full (16), api-only |
| **Scan Diff** | Scans vergleichen um Aenderungen zu tracken |
| **Scheduled Scans** | Cron-aehnliche Intervalle fuer Monitoring |
| **Report Export** | JSON, CSV, Markdown |

## Schnellstart

```bash
git clone https://github.com/timmeck/sentinel.git
cd sentinel
pip install -r requirements.txt
ollama pull qwen3:14b

# Eigene Seite scannen
python run.py scan https://deine-seite.com

# Dashboard
python run.py serve
# -> http://localhost:8500
```

## Wichtig

**Nur eigene Ziele oder mit Erlaubnis scannen.** Unauthorized Scanning ist in den meisten Laendern illegal.

## Support

[![Star this repo](https://img.shields.io/github/stars/timmeck/sentinel?style=social)](https://github.com/timmeck/sentinel)
[![PayPal](https://img.shields.io/badge/Donate-PayPal-blue)](https://paypal.me/tmeck86)

---

Gebaut von [Tim Mecklenburg](https://github.com/timmeck)
