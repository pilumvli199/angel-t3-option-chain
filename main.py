import os
import time
import threading
import logging
from flask import Flask, jsonify
import pyotp
import requests
from datetime import datetime, timedelta

# ---- SmartAPI import ----
SmartConnect = None
try:
    from SmartApi import SmartConnect as _SC
    SmartConnect = _SC
    logging.info("SmartConnect imported successfully!")
except Exception as e:
    logging.error(f"Failed to import SmartConnect: {e}")
    SmartConnect = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('angel-option-chain-bot')

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

def tele_send_http(chat_id: str, text: str):
    """Send message using Telegram Bot HTTP API via requests (synchronous)."""
    try:
        token = TELE_TOKEN
        if not token:
            logger.error('TELEGRAM_BOT_TOKEN not set, cannot send Telegram message.')
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        }
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code != 200:
            logger.warning('Telegram API returned %s: %s', r.status_code, r.text)
            return False
        return True
    except Exception as e:
        logger.exception('Failed to send Telegram message: %s', e)
        return False

def login_and_setup(api_key, client_id, password, totp_secret):
    if SmartConnect is None:
        raise RuntimeError('SmartAPI SDK not available. Check requirements.txt installation.')
    smartApi = SmartConnect(api_key=api_key)
    totp = pyotp.TOTP(totp_secret).now()
    logger.info('Logging in to SmartAPI...')
    data = smartApi.generateSession(client_id, password, totp)
    if not data or data.get('status') is False:
        raise RuntimeError(f"Login failed: {data}")
    authToken = data['data']['jwtToken']
    refreshToken = data['data']['refreshToken']
    try:
        feedToken = smartApi.getfeedToken()
    except Exception:
        feedToken = None
    try:
        smartApi.generateToken(refreshToken)
    except Exception:
        pass
    return smartApi, authToken, refreshToken, feedToken

def get_current_expiry():
    """Get current week's expiry (Thursday)"""
    today = datetime.now()
    days_ahead = 3 - today.weekday()  # Thursday is 3
    if days_ahead <= 0:
        days_ahead += 7
    expiry = today + timedelta(days=days_ahead)
    return expiry.strftime('%d%b%y').upper()

def download_instruments(smartApi):
    """Download instrument master file from Angel One"""
    try:
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            instruments = response.json()
            logger.info(f"Downloaded {len(instruments)} instruments")
            return instruments
        return None
    except Exception as e:
        logger.exception(f"Failed to download instruments: {e}")
        return None

def find_option_tokens(instruments, symbol, expiry, current_price):
    """Find option tokens for strikes around current price"""
    if not instruments:
        return []
    
    # Calculate ATM and surrounding strikes
    if symbol == "NIFTY":
        strike_gap = 50
    else:  # BANKNIFTY
        strike_gap = 100
    
    atm = round(current_price / strike_gap) * strike_gap
    strikes = []
    
    # Get 5 strikes above and 5 below ATM
    for i in range(-5, 6):
        strikes.append(atm + (i * strike_gap))
    
    option_tokens = []
    
    for instrument in instruments:
        if instrument.get('name') == symbol and instrument.get('expiry') == expiry:
            strike = float(instrument.get('strike', 0))
            if strike in strikes:
                option_type = instrument.get('symbol', '')[-2:]  # CE or PE
                token = instrument.get('token')
                option_tokens.append({
                    'strike': strike,
                    'type': option_type,
                    'token': token,
                    'symbol': instrument.get('symbol')
                })
    
    return sorted(option_tokens, key=lambda x: (x['strike'], x['type']))

def get_option_chain_data(smartApi, option_tokens):
    """Fetch option chain LTP data"""
    try:
        if not option_tokens:
            return {}
        
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-UserType': 'USER',
            'X-SourceID': 'WEB',
            'X-ClientLocalIP': '127.0.0.1',
            'X-ClientPublicIP': '127.0.0.1',
            'X-MACAddress': '00:00:00:00:00:00',
            'X-PrivateKey': API_KEY
        }
        
        # Split CE and PE tokens
        ce_tokens = [opt['token'] for opt in option_tokens if opt['type'] == 'CE']
        pe_tokens = [opt['token'] for opt in option_tokens if opt['type'] == 'PE']
        
        all_tokens = ce_tokens + pe_tokens
        
        payload = {
            "mode": "LTP",
            "exchangeTokens": {
                "NFO": all_tokens
            }
        }
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload,
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                result = {}
                fetched = data.get('data', {}).get('fetched', [])
                for item in fetched:
                    token = item.get('symbolToken', '')
                    ltp = float(item.get('ltp', 0))
                    result[token] = ltp
                return result
        
        return {}
        
    except Exception as e:
        logger.exception(f"Failed to fetch option chain data: {e}")
        return {}

def get_spot_prices(smartApi):
    """Get NIFTY and BANKNIFTY spot prices"""
    try:
        headers = {
            'Authorization': f'Bearer {smartApi.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-UserType': 'USER',
            'X-SourceID': 'WEB',
            'X-ClientLocalIP': '127.0.0.1',
            'X-ClientPublicIP': '127.0.0.1',
            'X-MACAddress': '00:00:00:00:00:00',
            'X-PrivateKey': API_KEY
        }
        
        payload = {
            "mode": "LTP",
            "exchangeTokens": {
                "NSE": ['99926000', '99926009']  # NIFTY, BANKNIFTY
            }
        }
        
        response = requests.post(
            'https://apiconnect.angelbroking.com/rest/secure/angelbroking/market/v1/quote/',
            json=payload,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                result = {}
                fetched = data.get('data', {}).get('fetched', [])
                for item in fetched:
                    token = item.get('symbolToken', '')
                    ltp = float(item.get('ltp', 0))
                    if token == '99926000':
                        result['NIFTY'] = ltp
                    elif token == '99926009':
                        result['BANKNIFTY'] = ltp
                return result
        
        return {}
        
    except Exception as e:
        logger.exception(f"Failed to fetch spot prices: {e}")
        return {}

def format_option_chain_message(symbol, spot_price, expiry, option_data, ltp_data):
    """Format option chain data for Telegram"""
    messages = []
    messages.append(f"📊 <b>{symbol} OPTION CHAIN</b>")
    messages.append(f"💰 Spot: ₹{spot_price:,.2f}")
    messages.append(f"📅 Expiry: {expiry}")
    messages.append(f"\n{'─'*35}")
    messages.append(f"<b>{'CALL':<12} {'STRIKE':>8} {'PUT':>12}</b>")
    messages.append(f"{'─'*35}")
    
    # Group by strike
    strikes = {}
    for opt in option_data:
        strike = opt['strike']
        if strike not in strikes:
            strikes[strike] = {'CE': 0, 'PE': 0}
        
        token = opt['token']
        ltp = ltp_data.get(token, 0)
        strikes[strike][opt['type']] = ltp
    
    # Display sorted by strike
    for strike in sorted(strikes.keys()):
        ce_ltp = strikes[strike]['CE']
        pe_ltp = strikes[strike]['PE']
        
        ce_str = f"₹{ce_ltp:.2f}" if ce_ltp > 0 else "-"
        pe_str = f"₹{pe_ltp:.2f}" if pe_ltp > 0 else "-"
        
        messages.append(f"{ce_str:<12} {int(strike):>8} {pe_str:>12}")
    
    messages.append(f"{'─'*35}")
    messages.append(f"🕐 {time.strftime('%H:%M:%S')}")
    
    return "\n".join(messages)

def bot_loop():
    if not all(REQUIRED):
        logger.error('Missing required environment variables. Bot will not start.')
        return

    try:
        smartApi, authToken, refreshToken, feedToken = login_and_setup(API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET)
        logger.info("✅ Login successful!")
    except Exception as e:
        logger.exception('Login/setup failed: %s', e)
        tele_send_http(TELE_CHAT_ID, f'❌ Login failed: {e}')
        return

    tele_send_http(TELE_CHAT_ID, f"✅ Option Chain Bot started!\n⏱ Polling every {POLL_INTERVAL}s")
    
    # Download instruments once
    logger.info("Downloading instruments...")
    instruments = download_instruments(smartApi)
    if not instruments:
        logger.error("Failed to download instruments")
        tele_send_http(TELE_CHAT_ID, "❌ Failed to download instruments")
        return
    
    expiry = get_current_expiry()
    logger.info(f"Current expiry: {expiry}")

    while True:
        try:
            # Get spot prices
            spot_prices = get_spot_prices(smartApi)
            
            if not spot_prices:
                logger.error("Failed to fetch spot prices")
                time.sleep(POLL_INTERVAL)
                continue
            
            # Process NIFTY
            if 'NIFTY' in spot_prices:
                nifty_price = spot_prices['NIFTY']
                nifty_options = find_option_tokens(instruments, 'NIFTY', expiry, nifty_price)
                
                if nifty_options:
                    ltp_data = get_option_chain_data(smartApi, nifty_options)
                    if ltp_data:
                        msg = format_option_chain_message('NIFTY 50', nifty_price, expiry, nifty_options, ltp_data)
                        tele_send_http(TELE_CHAT_ID, msg)
                        time.sleep(2)  # Small delay between messages
            
            # Process BANKNIFTY
            if 'BANKNIFTY' in spot_prices:
                bn_price = spot_prices['BANKNIFTY']
                bn_options = find_option_tokens(instruments, 'BANKNIFTY', expiry, bn_price)
                
                if bn_options:
                    ltp_data = get_option_chain_data(smartApi, bn_options)
                    if ltp_data:
                        msg = format_option_chain_message('BANK NIFTY', bn_price, expiry, bn_options, ltp_data)
                        tele_send_http(TELE_CHAT_ID, msg)
            
        except Exception as e:
            logger.exception(f"Error in bot loop: {e}")
            tele_send_http(TELE_CHAT_ID, f"⚠️ Error: {str(e)[:100]}")
        
        time.sleep(POLL_INTERVAL)

# Start bot in a background thread
thread = threading.Thread(target=bot_loop, daemon=True)
thread.start()

@app.route('/')
def index():
    status = {
        'bot_thread_alive': thread.is_alive(),
        'poll_interval': POLL_INTERVAL,
        'smartapi_sdk_available': SmartConnect is not None,
        'service': 'Option Chain Bot'
    }
    return jsonify(status)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'thread_alive': thread.is_alive()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
