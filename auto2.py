import asyncio
import aiohttp
import time
import hashlib
import json
import random
import sys
import io
import logging
from datetime import datetime
from pytz import timezone
from urllib.parse import quote
from aiohttp import ClientSession, ClientTimeout, ClientConnectionError, ServerDisconnectedError
from aiohttp_socks import ProxyConnector, ProxyType, ProxyError

CONFIGPROXY = "http://103.67.199.104:20051"
# Force UTF-8 encoding for console output
if sys.platform.startswith('win'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()
logging.getLogger("aiohttp").setLevel(logging.WARNING)

# Biến toàn cục lưu danh sách tỉnh
provinces = []

# Account state
class AccountState:
    def __init__(self):
        self.is_first_run = True
        self.account_nick = None
        self.share_count = 0
        self.max_shares = 999999999
        self.token = None

async def safe_request(session, method, url, **kwargs):
    """Gửi request có retry"""
    for attempt in range(5):
        try:
            if method == "POST":
                async with session.post(url, **kwargs) as resp:
                    resp.raise_for_status()
                    return resp
            else:
                async with session.get(url, **kwargs) as resp:
                    resp.raise_for_status()
                    return resp
        except (aiohttp.ClientError, aiohttp.http_exceptions.HttpProcessingError) as e:
            logger.warning(f"Lỗi request {url} (lần {attempt+1}): {e}")
            await asyncio.sleep(1)
    return None

async def login(key, account):

    async with aiohttp.ClientSession() as session:
        try:
            headers = {
                'origin': 'https://au.vtc.vn',
                'referer': 'https://au.vtc.vn',
                'sec-ch-ua': '"Android WebView";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
                'sec-ch-ua-mobile': '?1',
                'sec-ch-ua-platform': '"Android"',
                'content-type': 'application/x-www-form-urlencoded',
                'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36'
            }
            
            # Retry POST request
            resp = await safe_request(session, "POST", 'https://au.vtc.vn/header/Handler/Process.ashx?act=GetCookieAuthString', data=f'info={quote(key)}', headers=headers)
            if not resp:
                logger.warning(f"Thất bại lấy CookieAuthString sau 5 lần thử Zalopay: {account}")
                return None
            if resp.status == 200:
                data = await resp.json()
                if data['ResponseStatus'] != 1:
                    logger.warning(f'Đăng nhập thất bại: {account}')
                    return None
            else:
                logger.warning(f'Lỗi đăng nhập {account}: HTTP {resp.status}')
                return None
            
            # Retry GET request
            resp = await safe_request(session, "GET", 'https://au.vtc.vn', headers=headers)
            if not resp:
                logger.warning(f"Thất bại lấy token sau 5 lần thử: {account}")
                return None
            if resp.status == 200:
                data = await resp.text()
                try:
                    token_value = data.split('\\"tokenValue\\":\\"')[1].split('\\"')[0]
                    logger.info(f"Tài khoản {account}: Đã đăng nhập thành công")
                    return token_value
                except IndexError:
                    logger.warning(f'Lỗi phân tích token: {account}')
                    return None
            else:
                logger.warning(f'Lỗi lấy token {account}: HTTP {resp.status}')
                return None
        
        except Exception as e:
            logger.error(f'Lỗi đăng nhập {account}: {e}')
            return None

async def run_event_flow(username, key, state):
    timeout = aiohttp.ClientTimeout(total=5.0)
    connector = ProxyConnector.from_url(CONFIGPROXY)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        try:
            # Perform login to get token for this account
            if state.is_first_run:
                token = await login(key, username)
                if not token:
                    logger.error(f"Không thể lấy token cho tài khoản {username}")
                    return False
                state.token = token
                state.account_nick = username
                # state.is_first_run = False
            bearer_token = f"Bearer {state.token}"

            maker_code = "BEAuSN19"
            backend_key_sign = "de54c591d457ed1f1769dda0013c9d30f6fc9bbff0b36ea0a425233bd82a1a22"
            login_url = "https://apiwebevent.vtcgame.vn/besnau19home/Event"
            au_url = "https://au.vtc.vn"

            def get_current_timestamp():
                return int(time.time())

            def sha256_hex(data):
                return hashlib.sha256(data.encode('utf-8')).hexdigest()

            async def generate_sign(ts, func):
                raw = f"{ts}{maker_code}{func}{backend_key_sign}"
                return sha256_hex(raw)

            browser_headers = { 
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Referer": "https://au.vtc.vn/",
                "Accept-Language": "en-US,en;q=0.9,vi;q=0.8", 
            }

            mission_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "Authorization": bearer_token,
                "Referer": au_url
            }

            async def send_wish(account_nick):
                global provinces
                if not provinces:
                    logger.info(f"Tài khoản {account_nick}: Lấy danh sách tỉnh...")
                    ts = get_current_timestamp()
                    sign = await generate_sign(ts, "wish-get-list")
                    payload = {
                        "time": ts,
                        "fromIP": "",
                        "sign": sign,
                        "makerCode": maker_code,
                        "func": "wish-get-list",
                        "data": ""
                    }
                    resp = await safe_request(session, "POST", login_url, json=payload, headers=mission_headers)
                    if not resp:
                        return None
                    data = await resp.json()
                    if data.get("code") != 1:
                        logger.warning(f"Tài khoản {account_nick}: Lấy danh sách tỉnh thất bại.")
                        return None
                    provinces = data["data"]["list"]
                    logger.info(f"Tài khoản {account_nick}: Có {len(provinces)} tỉnh.")

                if not provinces:
                    return None

                selected = random.choice(provinces)
                ts = get_current_timestamp()
                sign = await generate_sign(ts, "wish-send")
                payload = {
                    "time": ts,
                    "fromIP": "",
                    "sign": sign,
                    "makerCode": maker_code,
                    "func": "wish-send",
                    "data": {
                        "FullName": account_nick,
                        "Avatar": selected["Avatar"],
                        "ProvinceID": selected["ProvinceID"],
                        "ProvinceName": selected["ProvinceName"],
                        "Content": "Chúc sự kiện thành công!"
                    }
                }
                resp = await safe_request(session, "POST", login_url, json=payload, headers=mission_headers)
                if not resp:
                    return None
                res = await resp.json()
                if res.get("mess") != "Gửi lời chúc thành công!":
                    return None
                logger.info(f"Tài khoản {username}: Gửi lời chúc thành công! ({selected['ProvinceName']})")
                return res["code"], ts

            async def perform_share(log_id, account_nick, username, wish_time):
                share_raw = f"{wish_time}{maker_code}{au_url}{backend_key_sign}"
                share_sign = sha256_hex(share_raw)
                share_url = f"{au_url}/bsau/api/generate-share-token?username={username}&time={wish_time}&sign={share_sign}"
                resp = await safe_request(session, "GET", share_url, headers=browser_headers)
                if not resp or 'application/json' not in resp.headers.get('content-type', ''):
                    return False
                token_data = await resp.json()
                share_token = token_data.get("token")
                if not share_token:
                    return False

                ts = get_current_timestamp()
                final_sign = await generate_sign(ts, "wish-share")
                payload = {
                    "time": ts,
                    "fromIP": "",
                    "sign": final_sign,
                    "makerCode": maker_code,
                    "func": "wish-share",
                    "data": {
                        "LogID": log_id,
                        "key": share_token,
                        "timestamp": ts,
                        "a": "aa"
                    }
                }
                res = await safe_request(session, "POST", login_url, json=payload, headers=mission_headers)
                if not res:
                    return False
                res_json = await res.json()
                logger.info(f"Tài khoản {account_nick}: {res_json}")
                return res_json.get("code") == 1

            if state.share_count >= state.max_shares:
                return False

            result = await send_wish(state.account_nick)
            if not result:
                return False
            log_id, wish_time = result

            if await perform_share(log_id, state.account_nick, username, wish_time):
                state.share_count += 1
                return True
            return False

        except Exception as e:
            logger.error(f"Lỗi {username}: {e}")
            return False

async def load_accounts():
    """Tải tài khoản và key từ file account.txt"""
    accounts = []
    try:
        with open('account.txt', 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    account, encoded_key = line.strip().split('|')
                    key = bytes.fromhex(encoded_key).decode('utf-8')
                    accounts.append((account, key))
    except Exception as e:
        logger.error(f"Lỗi đọc file account.txt: {e}")
    return accounts

async def main():
    accounts = await load_accounts()
    if not accounts:
        logger.error("Không có tài khoản nào để xử lý.")
        return

    sem = asyncio.Semaphore(2)

    async def process_account(username, key, state):
        async with sem:
            ok = await run_event_flow(username, key, state)
            await asyncio.sleep(2)
            return ok

    states = {u: AccountState() for u, _ in accounts}
    while True:
        logger.info("Bắt đầu xử lý từ đầu danh sách tài khoản")
        tasks = [process_account(u, k, states[u]) for u, k in accounts]
        await asyncio.gather(*tasks)
        logger.info("Đã xử lý xong tất cả tài khoản, quay lại từ đầu")
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())