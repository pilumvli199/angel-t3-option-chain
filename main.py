import os
import time
import threading
import logging
from pathlib import Path
from flask import Flask, jsonify
import pyotp
from SmartApi.smartConnect import SmartConnect
from telegram import Bot

# Basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('angel-railway-bot')

# Load config from env
API_KEY = os.getenv('SMARTAPI_API_KEY')
CLIENT_ID = os.getenv('SMARTAPI_CLIENT_ID')
PASSWORD = os.getenv('SMARTAPI_PASSWORD')
TOTP_SECRET = os.getenv('SMARTAPI_TOTP_SECRET')
TELE_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELE_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 60)

REQUIRED = [API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET, TELE_TOKEN, TELE_CHAT_ID]

app = Flask(__name__)

def tele_send(bot: Bot, chat_id: str, text: str):
    try:
        bot.send_message(chat_id=chat_id, text=text)
    except Exception as e:
        logger.exception('Telegram send failed: %s', e)

def login_and_setup(api_key, client_id, password, totp_secret):
    smartApi = SmartConnect(api_key=api_key)
    totp = pyotp.TOTP(totp_secret).now()
    logger.info('Logging in to SmartAPI...')
    data = smartApi.generateSession(client_id, password, totp)
    if not data or data.get('status') is False:
        raise RuntimeError(f"Login failed: {data}")
    authToken = data['data']['jwtToken']
    refreshToken = data['data']['refreshToken']
    logger.info('Login successful, fetching feed token...')
    try:
        feedToken = smartApi.getfeedToken()
    except Exception:
        feedToken = None
    # generateToken if needed
    try:
        smartApi.generateToken(refreshToken)
    except Exception:
        logger.debug('generateToken not required or failed silently')
    return smartApi, authToken, refreshToken, feedToken

def find_symboltoken_for_query(smartApi, query):
    logger.info(f"Searching symbol for: {query}")
    try:
        res = smartApi.searchScrip(query)
    except TypeError:
        try:
            res = smartApi.searchScrip('NSE', query)
        except Exception as e:
            logger.exception('searchScrip failed: %s', e)
            return None
    except Exception as e:
        logger.exception('searchScrip failed: %s', e)
        return None

    try:
        candidates = res.get('data') if isinstance(res, dict) and 'data' in res else res
        if not candidates:
            return None
        first = candidates[0]
        token = first.get('symboltoken') or first.get('token') or first.get('symbolToken')
        tradingsymbol = first.get('tradingsymbol') or first.get('tradingsymbol') or first.get('symbol')
        return {'symboltoken': str(token), 'tradingsymbol': tradingsymbol}
    except Exception:
        logger.exception('Parsing searchScrip response failed')
        return None

def get_ltp(smartApi, exchange, tradingsymbol, symboltoken):
    try:
        data = smartApi.ltpData(exchange, tradingsymbol, symboltoken)
        if isinstance(data, dict) and data.get('status') is not False:
            d = data.get('data') if isinstance(data.get('data'), dict) else data
            ltp = None
            if isinstance(d, dict):
                ltp = d.get('ltp') or d.get('last_price') or d.get('ltpValue')
            if ltp is None and isinstance(d, list) and len(d) > 0:
                entry = d[0]
                ltp = entry.get('ltp') or entry.get('last_price')
            return float(ltp) if ltp is not None else None
        else:
            logger.warning('ltpData returned unexpected: %s', data)
            return None
    except Exception:
        logger.exception('ltpData call failed')
        return None

def bot_loop():
    if not all(REQUIRED):
        logger.error('Missing required environment variables. Bot will not start.')
        return

    bot = Bot(token=TELE_TOKEN)

    try:
        smartApi, authToken, refreshToken, feedToken = login_and_setup(API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET)
    except Exception as e:
        logger.exception('Login/setup failed: %s', e)
        tele_send(bot, TELE_CHAT_ID, f'Login failed: {e}')
        return

    targets = ['NIFTY 50', 'SENSEX']
    found = {}
    for t in targets:
        info = find_symboltoken_for_query(smartApi, t)
        if not info:
            logger.warning('Could not find symbol for %s', t)
            tele_send(bot, TELE_CHAT_ID, f'Could not find symbol token for {t}.')
        else:
            found[t] = info

    if not found:
        logger.error('No symbols found. Exiting bot loop.')
        tele_send(bot, TELE_CHAT_ID, 'No symbols found; bot stopped.')
        return

    tele_send(bot, TELE_CHAT_ID, f"Bot started. Polling every {POLL_INTERVAL}s for: {', '.join(found.keys())}")

    while True:
        messages = []
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        for name, info in found.items():
            ltp = get_ltp(smartApi, 'NSE', info.get('tradingsymbol') or '', info.get('symboltoken') or '')
            if ltp is None:
                messages.append(f"{ts} | {name}: LTP not available")
            else:
                messages.append(f"{ts} | {name}: {ltp}")
        text = "\\n".join(messages)
        logger.info('Sending message:\\n%s', text)
        tele_send(bot, TELE_CHAT_ID, text)
        time.sleep(POLL_INTERVAL)

# Start bot in a background thread at import time so Gunicorn/Procfile runs it.
thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

# Minimal Flask app for healthcheck
@app.route('/')
def index():
    status = {
        'bot_thread_alive': thread.is_alive(),
        'poll_interval': POLL_INTERVAL
    }
    return jsonify(status)

# Expose app for gunicorn: `gunicorn main:app`
if __name__ == '__main__':
    # allow running locally with `python main.py`
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
