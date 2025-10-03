# Angel One (SmartAPI) -> Telegram LTP Bot (Railway-ready)

This project polls Angel One (SmartAPI) for NIFTY 50 and SENSEX LTP every `POLL_INTERVAL` seconds and sends updates to a Telegram chat.

Files:
- `main.py` : Main application. Contains a lightweight Flask `app` for health checks and starts the polling background thread at import time.
- `requirements.txt` : Python dependencies.
- `.env.example` : Environment variables example. Copy to `.env` and set real values.
- `Procfile` : For Railway/Heroku-style deployment using Gunicorn.

Deployment notes:
- Copy `.env.example` -> `.env` and fill values.
- Push to Railway with Python environment. Railway will run the `web` process via Procfile.
- The process uses a background thread to send Telegram messages; Gunicorn imports `main` which starts the thread automatically.

Caveats:
- Check SmartAPI rate limits. If you need faster updates, use SmartAPI WebSocket feed instead of polling.
- Keep secrets out of source control. Use Railway environment variables or secrets to store credentials.
