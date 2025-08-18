import asyncio
import httpx
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

# Force UTF-8 encoding for console output
if sys.platform.startswith('win'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()
logging.getLogger("httpx").setLevel(logging.WARNING)

# Biến toàn cục lưu danh sách tỉnh
provinces = []

# Danh sách proxy hard code
PROXIES = [
    "http://103.67.199.104:20051",
]

# Trạng thái tài khoản
class AccountState:
    def __init__(self):
        self.is_first_run = True
        self.account_nick = None
        self.share_count = 0
        self.max_shares = 999999999
        self.token = None
        self.proxy = None

async def check_proxy(client, proxy):
    """Kiểm tra kết nối proxy"""
    for attempt in range(5):
        try:
            resp = await client.get('https://api.ipify.org', timeout=5.0)
            resp.raise_for_status()
            ip = resp.text
            logger.info(f"Proxy {proxy} hoạt động, IP: {ip}")
            return True
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning(f"Lỗi kiểm tra proxy {proxy} (lần {attempt+1}): {e}")
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
    logger.error(f"Proxy {proxy} không hoạt động sau 5 lần thử")
    return False

async def safe_request(client, method, url, **kwargs):
    """Gửi request có retry"""
    for attempt in range(5):
        try:
            if method == "POST":
                resp = await client.post(url, **kwargs)
            else:
                resp = await client.get(url, **kwargs)
            resp.raise_for_status()
            return resp
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning(f"Lỗi request {url} (lần {attempt+1}): {e}")
            await asyncio.sleep(1)
    return None

async def login(client: httpx.AsyncClient, key, account, proxy):
    """Đăng nhập để lấy token với retry"""
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
        resp = await safe_request(client, "POST", 'https://au.vtc.vn/header/Handler/Process.ashx?act=GetCookieAuthString', data=f'info={quote(key)}', headers=headers)
        if not resp:
            logger.warning(f"Thất bại lấy CookieAuthString sau 5 lần thử: {account} (proxy: {proxy})")
            return None
        if resp.status_code == 200:
            data = resp.json()
            if data['ResponseStatus'] != 1:
                logger.warning(f'Đăng nhập thất bại: {account} (proxy: {proxy})')
                return None
        else:
            logger.warning(f'Lỗi đăng nhập {account} (proxy: {proxy}): HTTP {resp.status_code}')
            return None
        
        # Retry GET request
        resp = await safe_request(client, "GET", 'https://au.vtc.vn', headers=headers)
        if not resp:
            logger.warning(f"Thất bại lấy token sau 5 lần thử: {account} (proxy: {proxy})")
            return None
        if resp.status_code == 200:
            data = resp.text
            try:
                token_value = data.split('\\"tokenValue\\":\\"')[1].split('\\"')[0]
                logger.info(f"Tài khoản {account}: Đã đăng nhập thành công (proxy: {proxy})")
                return token_value
            except IndexError:
                logger.warning(f'Lỗi phân tích token: {account} (proxy: {proxy})')
                return None
        else:
            logger.warning(f'Lỗi lấy token {account} (proxy: {proxy}): HTTP {resp.status_code}')
            return None
    
    except Exception as e:
        logger.error(f'Lỗi đăng nhập {account} (proxy: {proxy}): {e}')
        return None

async def run_event_flow(client: httpx.AsyncClient, username, key, state):
    global provinces
    try:
        # Kiểm tra proxy trước khi xử lý
        if not await check_proxy(client, state.proxy):
            logger.error(f"Tài khoản {username}: Proxy {state.proxy} không hoạt động, bỏ qua")
            return False

        # Đăng nhập để lấy token nếu là lần chạy đầu tiên
        if state.is_first_run:
            token = await login(client, key, username, state.proxy)
            if not token:
                logger.error(f"Không thể lấy token cho tài khoản {username} (proxy: {state.proxy})")
                return False
            state.token = token
            state.account_nick = username
            state.is_first_run = False  # Chỉ đăng nhập một lần

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
                logger.info(f"Tài khoản {account_nick}: Lấy danh sách tỉnh (proxy: {state.proxy})...")
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
                resp = await safe_request(client, "POST", login_url, json=payload, headers=mission_headers)
                if not resp:
                    return None
                data = resp.json()
                if data.get("code") != 1:
                    logger.warning(f"Tài khoản {account_nick}: Lấy danh sách tỉnh thất bại (proxy: {state.proxy})")
                    return None
                provinces = data["data"]["list"]
                logger.info(f"Tài khoản {account_nick}: Có {len(provinces)} tỉnh (proxy: {state.proxy})")

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
            resp = await safe_request(client, "POST", login_url, json=payload, headers=mission_headers)
            if not resp:
                return None
            res = resp.json()
            if res.get("mess") != "Gửi lời chúc thành công!":
                return None
            logger.info(f"Tài khoản {username}: Gửi lời chúc thành công! ({selected['ProvinceName']}) (proxy: {state.proxy})")
            return res["code"], ts

        async def perform_share(log_id, account_nick, username, wish_time):
            share_raw = f"{wish_time}{maker_code}{au_url}{backend_key_sign}"
            share_sign = sha256_hex(share_raw)
            share_url = f"{au_url}/bsau/api/generate-share-token?username={username}&time={wish_time}&sign={share_sign}"
            resp = await safe_request(client, "GET", share_url, headers=browser_headers)
            if not resp or 'application/json' not in resp.headers.get('Content-Type', ''):
                return False
            token_data = resp.json()
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
            res = await safe_request(client, "POST", login_url, json=payload, headers=mission_headers)
            if not res:
                return False
            logger.info(f"Tài khoản {account_nick}: {res.json()} (proxy: {state.proxy})")
            return res.json().get("code") == 1

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
        logger.error(f"Lỗi {username} (proxy: {state.proxy}): {e}")
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

    proxies = PROXIES
    if not proxies:
        logger.warning("Không có proxy nào được cấu hình, chạy không proxy.")

    sem = asyncio.Semaphore(2)

    async def process_account(username, key, state):
        async with sem:
            # Tạo client riêng cho từng tài khoản với proxy tương ứng
            proxy = state.proxy if state.proxy else None
            async with httpx.AsyncClient(proxies=proxy, limits=httpx.Limits(max_connections=500, max_keepalive_connections=500), timeout=5.0, http2=True) as client:
                ok = await run_event_flow(client, username, key, state)
                await asyncio.sleep(2)
                return ok

    # Gán proxy cho từng tài khoản
    states = {u: AccountState() for u, _ in accounts}
    for i, (username, _) in enumerate(accounts):
        states[username].proxy = proxies[i % len(proxies)] if proxies else None
        logger.info(f"Tài khoản {username}: Sử dụng proxy {states[username].proxy}")

    while True:
        logger.info("Bắt đầu xử lý từ đầu danh sách tài khoản")
        tasks = [process_account(u, k, states[u]) for u, k in accounts]
        await asyncio.gather(*tasks)
        logger.info("Đã xử lý xong tất cả tài khoản, quay lại từ đầu")
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())