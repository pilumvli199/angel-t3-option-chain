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

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
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
    logger.info(f"✅ Login successful! Auth token: {authToken[:20]}...")
    try:
        feedToken = smartApi.getfeedToken()
        logger.info(f"Feed token: {feedToken}")
    except Exception as e:
        logger.warning(f"Feed token failed: {e}")
        feedToken = None
    try:
        smartApi.generateToken(refreshToken)
    except Exception:
        pass
    return smartApi, authToken, refreshToken, feedToken

def get_nifty_expiry():
    """Get NIFTY 50 weekly expiry (next Tuesday)"""
    today = datetime.now()
    # Tuesday is 1 (Monday=0, Tuesday=1, ...)
    days_ahead = 1 - today.weekday()
    if days_ahead <= 0:  # If today is Tuesday or later, get next Tuesday
        days_ahead += 7
    expiry = today + timedelta(days=days_ahead)
    # Format: DDMMMYYYY (e.g., 07OCT2025) - Angel One uses 4-digit year
    return expiry.strftime('%d%b%Y').upper()

def get_banknifty_expiry():
    """Get BANKNIFTY monthly expiry (last Wednesday of month)"""
    today = datetime.now()
    # Get last day of current month
    if today.month == 12:
        next_month = datetime(today.year + 1, 1, 1)
    else:
        next_month = datetime(today.year, today.month + 1, 1)
    
    last_day = next_month - timedelta(days=1)
    
    # Find last Wednesday (weekday 2)
    days_back = (last_day.weekday() - 2) % 7
    last_wednesday = last_day - timedelta(days=days_back)
    
    # Format: DDMMMYYYY (e.g., 30OCT2025) - Angel One uses 4-digit year
    return last_wednesday.strftime('%d%b%Y').upper()

def parse_expiry_formats(expiry_str):
    """Parse different expiry date formats from Angel One
    Returns datetime object or None
    """
    if not expiry_str:
        return None
    
    formats = [
        '%d%b%Y',  # 07OCT2025
        '%d%b%y',  # 07OCT25
        '%Y-%m-%d',  # 2025-10-07
        '%d-%m-%Y',  # 07-10-2025
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(str(expiry_str), fmt)
        except:
            continue
    return None

def download_instruments(smartApi):
    """Download instrument master file from Angel One"""
    try:
        logger.info("📥 Downloading instruments master file...")
        url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            instruments = response.json()
            logger.info(f"✅ Downloaded {len(instruments)} instruments")
            
            # Count NIFTY and BANKNIFTY options
            nifty_count = sum(1 for i in instruments if i.get('name') == 'NIFTY')
            bn_count = sum(1 for i in instruments if i.get('name') == 'BANKNIFTY')
            logger.info(f"📊 NIFTY options: {nifty_count}, BANKNIFTY options: {bn_count}")
            
            return instruments
        else:
            logger.error(f"Failed to download instruments: {response.status_code}")
        return None
    except Exception as e:
        logger.exception(f"❌ Failed to download instruments: {e}")
        return None

def find_option_tokens(instruments, symbol, target_expiry, current_price):
    """Find option tokens for strikes around current price"""
    if not instruments:
        logger.error("No instruments available!")
        return []
    
    logger.info(f"🔍 Finding options for {symbol}, Target Expiry: {target_expiry}, Price: {current_price}")
    
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
    
    logger.info(f"🎯 ATM: {atm}, Looking for strikes: {strikes[:3]}...{strikes[-3:]}")
    
    option_tokens = []
    expiry_samples = set()
    
    for instrument in instruments:
        inst_name = instrument.get('name', '')
        inst_expiry = instrument.get('expiry', '')
        
        # Collect expiry samples for debugging
        if inst_name == symbol and inst_expiry:
            expiry_samples.add(inst_expiry)
        
        # Direct string match for expiry
        if inst_name == symbol and inst_expiry == target_expiry:
            strike = float(instrument.get('strike', 0))
            if strike > 0 and strike in strikes:
                symbol_name = instrument.get('symbol', '')
                option_type = 'CE' if 'CE' in symbol_name else 'PE'
                token = instrument.get('token')
                option_tokens.append({
                    'strike': strike,
                    'type': option_type,
                    'token': token,
                    'symbol': symbol_name,
                    'expiry': inst_expiry
                })
    
    logger.info(f"📋 Found {len(expiry_samples)} unique expiries for {symbol}")
    logger.info(f"✅ Found {len(option_tokens)} option contracts matching {target_expiry}")
    
    if option_tokens:
        logger.info(f"Sample matched options: {option_tokens[:2]}")
    else:
        available = sorted(list(expiry_samples))[:10]
        logger.warning(f"⚠️ No options found!")
        logger.warning(f"Target: {target_expiry}, Available: {available}")
    
    return sorted(option_tokens, key=lambda x: (x['strike'], x['type']))

def get_option_chain_data(smartApi, option_tokens):
    """Fetch option chain LTP data"""
    try:
        if not option_tokens:
            logger.warning("No option tokens provided")
            return {}
        
        logger.info(f"📡 Fetching LTP for {len(option_tokens)} options...")
        
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
        
        all_tokens = [opt['token'] for opt in option_tokens]
        logger.debug(f"Tokens to fetch: {all_tokens[:5]}...")
        
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
        
        logger.info(f"API Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            logger.debug(f"Response data: {data}")
            
            if data.get('status'):
                result = {}
                fetched = data.get('data', {}).get('fetched', [])
                logger.info(f"✅ Fetched data for {len(fetched)} instruments")
                
                for item in fetched:
                    token = item.get('symbolToken', '')
                    ltp = float(item.get('ltp', 0))
                    result[token] = ltp
                
                if result:
                    logger.info(f"Sample LTP data: {list(result.items())[:3]}")
                return result
            else:
                logger.error(f"API returned status=false: {data}")
        else:
            logger.error(f"API error: {response.text}")
        
        return {}
        
    except Exception as e:
        logger.exception(f"❌ Failed to fetch option chain data: {e}")
        return {}

def get_spot_prices(smartApi):
    """Get NIFTY and BANKNIFTY spot prices"""
    try:
        logger.info("📊 Fetching spot prices...")
        
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
        
        logger.info(f"Spot API Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status'):
                result = {}
                fetched = data.get('data', {}).get('fetched', [])
                logger.info(f"Spot data fetched: {len(fetched)} indices")
                
                for item in fetched:
                    token = item.get('symbolToken', '')
                    ltp = float(item.get('ltp', 0))
                    if token == '99926000':
                        result['NIFTY'] = ltp
                        logger.info(f"✅ NIFTY: ₹{ltp:,.2f}")
                    elif token == '99926009':
                        result['BANKNIFTY'] = ltp
                        logger.info(f"✅ BANKNIFTY: ₹{ltp:,.2f}")
                return result
            else:
                logger.error(f"Spot API status=false: {data}")
        else:
            logger.error(f"Spot API error: {response.text}")
        
        return {}
        
    except Exception as e:
        logger.exception(f"❌ Failed to fetch spot prices: {e}")
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
        logger.error('❌ Missing required environment variables. Bot will not start.')
        return

    try:
        smartApi, authToken, refreshToken, feedToken = login_and_setup(API_KEY, CLIENT_ID, PASSWORD, TOTP_SECRET)
        logger.info("✅ Login successful!")
    except Exception as e:
        logger.exception('❌ Login/setup failed: %s', e)
        tele_send_http(TELE_CHAT_ID, f'❌ Login failed: {e}')
        return

    tele_send_http(TELE_CHAT_ID, f"✅ Option Chain Bot started!\n⏱ Polling every {POLL_INTERVAL}s\n🔄 Initializing...")
    
    # Download instruments once
    logger.info("📥 Downloading instruments...")
    instruments = download_instruments(smartApi)
    if not instruments:
        error_msg = "❌ Failed to download instruments. Bot cannot continue."
        logger.error(error_msg)
        tele_send_http(TELE_CHAT_ID, error_msg)
        return
    
    nifty_expiry = get_nifty_expiry()
    banknifty_expiry = get_banknifty_expiry()
    logger.info(f"📅 NIFTY expiry: {nifty_expiry}, BANKNIFTY expiry: {banknifty_expiry}")
    tele_send_http(TELE_CHAT_ID, f"📅 NIFTY expiry: {nifty_expiry}\n📅 BANKNIFTY expiry: {banknifty_expiry}")

    iteration = 0
    while True:
        try:
            iteration += 1
            logger.info(f"\n{'='*50}")
            logger.info(f"🔄 Iteration #{iteration} - {time.strftime('%H:%M:%S')}")
            logger.info(f"{'='*50}")
            
            # Get spot prices
            spot_prices = get_spot_prices(smartApi)
            
            # If market closed, use dummy prices for testing
            if not spot_prices or all(v == 0 for v in spot_prices.values()):
                logger.warning("⚠️ Market appears to be closed. Using dummy prices for testing.")
                spot_prices = {'NIFTY': 25000, 'BANKNIFTY': 52000}
            
            # Process NIFTY
            if 'NIFTY' in spot_prices:
                logger.info(f"\n--- Processing NIFTY ---")
                nifty_price = spot_prices['NIFTY']
                nifty_options = find_option_tokens(instruments, 'NIFTY', nifty_expiry, nifty_price)
                
                if nifty_options:
                    ltp_data = get_option_chain_data(smartApi, nifty_options)
                    if ltp_data:
                        msg = format_option_chain_message('NIFTY 50', nifty_price, nifty_expiry, nifty_options, ltp_data)
                        tele_send_http(TELE_CHAT_ID, msg)
                        logger.info("✅ NIFTY data sent to Telegram")
                        time.sleep(2)
                    else:
                        logger.warning("⚠️ No LTP data received for NIFTY options")
                else:
                    logger.warning("⚠️ No NIFTY option contracts found")
            
            # Process BANKNIFTY
            if 'BANKNIFTY' in spot_prices:
                logger.info(f"\n--- Processing BANKNIFTY ---")
                bn_price = spot_prices['BANKNIFTY']
                bn_options = find_option_tokens(instruments, 'BANKNIFTY', banknifty_expiry, bn_price)
                
                if bn_options:
                    ltp_data = get_option_chain_data(smartApi, bn_options)
                    if ltp_data:
                        msg = format_option_chain_message('BANK NIFTY', bn_price, banknifty_expiry, bn_options, ltp_data)
                        tele_send_http(TELE_CHAT_ID, msg)
                        logger.info("✅ BANKNIFTY data sent to Telegram")
                    else:
                        logger.warning("⚠️ No LTP data received for BANKNIFTY options")
                else:
                    logger.warning("⚠️ No BANKNIFTY option contracts found")
            
            logger.info(f"✅ Iteration #{iteration} complete. Sleeping {POLL_INTERVAL}s...")
            
        except Exception as e:
            logger.exception(f"❌ Error in bot loop iteration #{iteration}: {e}")
            tele_send_http(TELE_CHAT_ID, f"⚠️ Error #{iteration}: {str(e)[:100]}")
        
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
        'service': 'Angel One Option Chain Bot',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    return jsonify(status)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'thread_alive': thread.is_alive()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))
