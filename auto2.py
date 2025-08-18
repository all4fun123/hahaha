import asyncio
import aiohttp
import time
import hashlib
import logging
import re
from datetime import datetime
from pytz import timezone
from aiohttp import ClientSession, ClientTimeout, ClientConnectionError, ServerDisconnectedError
from aiohttp_socks import ProxyConnector, ProxyType, ProxyError
from urllib.parse import quote
import os
from typing import Optional, List, Tuple

# Cấu hình
CONFIGPROXY = 'http://103.67.199.104:20051/'
FILE_NAME = 'account.txt'
TIMEOUT = 10
MAX_TOKEN_RETRIES = 20
MAX_SESSION_RETRIES = 20
RETRY_DELAY = 1
API_URL = "https://apiwebevent.vtcgame.vn/besnau19/Event"
MAKER_CODE = "BEAuSN19"
BACKEND_KEY_SIGN = "de54c591d457ed1f1769dda0013c9d30f6fc9bbff0b36ea0a425233bd82a1a22"
AU_URL = "https://au.vtc.vn"

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('share_event_log.txt', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

class AccountState:
    def __init__(self):
        self.account_nick: Optional[str] = None
        self.share_count: int = 0
        self.provinces: List[dict] = []

async def get_token(key: str, account: str, retry: int = 0) -> Optional[str]:
    """Lấy token xác thực cho tài khoản."""
    if retry >= MAX_TOKEN_RETRIES:
        logger.error(f"{account}: Không lấy được token sau {MAX_TOKEN_RETRIES} lần thử")
        return None

    headers = {
        'origin': 'https://au.vtc.vn',
        'referer': 'https://au.vtc.vn/auparty',
        'sec-ch-ua': '"Android WebView";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'content-type': 'application/x-www-form-urlencoded',
        'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36'
    }

    async with ClientSession(headers=headers, timeout=ClientTimeout(total=TIMEOUT)) as session:
        try:
            async with session.post(
                'https://au.vtc.vn/header/Handler/Process.ashx?act=GetCookieAuthString',
                data=f'info={quote(key)}',
                ssl=True
            ) as response:
                if response.status != 200:
                    logger.warning(f"{account}: Đăng nhập thất bại, mã trạng thái: {response.status} (thử lần {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)
                try:
                    data = await response.json()
                except aiohttp.ContentTypeError:
                    logger.warning(f"{account}: Phản hồi JSON không hợp lệ khi đăng nhập (thử lần {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)
                if data.get('ResponseStatus') != 1:
                    logger.warning(f"{account}: Đăng nhập thất bại: {data.get('ResponseMessage', 'Không có thông báo')} (thử lần {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)
                logger.info(f"{account}: Đăng nhập thành công")

            async with session.get('https://au.vtc.vn/auparty', ssl=True) as response:
                if response.status != 200:
                    logger.warning(f"{account}: Không truy cập được trang auparty, mã trạng thái: {response.status} (thử lần {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)
                data = await response.text()
                match = re.search(r'\\"tokenValue\\":\\"(.*?)\\"', data)
                if match:
                    token_value = match.group(1)
                    logger.info(f"{account}: Lấy token thành công")
                    return token_value
                else:
                    logger.warning(f"{account}: Không trích xuất được tokenValue (thử lần {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)

        except (ClientConnectionError, ServerDisconnectedError) as e:
            logger.warning(f"{account}: Lỗi mạng khi lấy token: {str(e)} (thử lần {retry + 1}/{MAX_TOKEN_RETRIES})")
            await asyncio.sleep(RETRY_DELAY)
            return await get_token(key, account, retry + 1)
        except Exception as e:
            logger.error(f"{account}: Lỗi không mong muốn khi lấy token: {str(e)} (thử lần {retry + 1}/{MAX_TOKEN_RETRIES})")
            await asyncio.sleep(RETRY_DELAY)
            return await get_token(key, account, retry + 1)

async def share_event_flow(username: str, bearer_token: str, state: AccountState) -> bool:
    """Thực hiện quy trình chia sẻ sự kiện cho tài khoản."""
    # connector = ProxyConnector.from_url(CONFIGPROXY) if CONFIGPROXY else None
    async with ClientSession(timeout=ClientTimeout(total=TIMEOUT)) as session:
        try:
            if CONFIGPROXY:
                for retry in range(20):
                    try:
                        async with session.get('http://ip-api.com/json', ssl=True, timeout=ClientTimeout(total=TIMEOUT)) as response:
                            if response.status == 200:
                                data = await response.json()
                                logger.info(f"Proxy hoạt động: IP {data.get('query', 'không xác định')}, Quốc gia: {data.get('country', 'không xác định')}")
                                break
                            else:
                                logger.warning(f"{username}: Kiểm tra proxy thất bại, mã trạng thái: {response.status} (thử lần {retry + 1}/3)")
                                if retry < 2:
                                    await asyncio.sleep(RETRY_DELAY)
                                continue
                    except (ClientConnectionError, ServerDisconnectedError, ProxyError) as e:
                        logger.warning(f"{username}: Lỗi mạng proxy: {str(e)} (thử lần {retry + 1}/3)")
                        if retry < 2:
                            await asyncio.sleep(RETRY_DELAY)
                        continue
                    except Exception as e:
                        logger.error(f"{username}: Lỗi không mong muốn khi kiểm tra proxy: {str(e)} (thử lần {retry + 1}/3)")
                        if retry < 2:
                            await asyncio.sleep(RETRY_DELAY)
                        continue
                else:
                    logger.error(f"{username}: Proxy không sử dụng được sau 3 lần thử")
                    return False

            def get_current_timestamp() -> int:
                return int(time.time())

            async def generate_sign(time: int, func: str) -> str:
                raw = f"{time}{MAKER_CODE}{func}{BACKEND_KEY_SIGN}"
                return hashlib.sha256(raw.encode('utf-8')).hexdigest()

            mission_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "Authorization": f"Bearer {bearer_token}",
                "Accept-Language": "en-US,en;q=0.9,vi;q=0.8",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Priority": "u=1, i",
                "Sec-Ch-Ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
            }

            async def send_wish(session: ClientSession, retry: int = 0) -> Optional[Tuple[int, int]]:
                if retry >= MAX_SESSION_RETRIES:
                    logger.warning(f"{username}: Không gửi được lời chúc sau {MAX_SESSION_RETRIES} lần thử")
                    return None

                if not state.provinces:
                    logger.info(f"{username}: Đang lấy danh sách tỉnh...")
                    get_list_time = get_current_timestamp()
                    get_list_sign = await generate_sign(get_list_time, "wish-get-list")
                    list_payload = {
                        "time": get_list_time,
                        "fromIP": "",
                        "sign": get_list_sign,
                        "makerCode": MAKER_CODE,
                        "func": "wish-get-list",
                        "data": ""
                    }
                    try:
                        async with session.post(API_URL, json=list_payload, headers=mission_headers, ssl=True) as response:
                            list_res = await response.json()
                        await asyncio.sleep(1)
                        if list_res.get("code") != 1:
                            logger.warning(f"{username}: Không lấy được danh sách tỉnh: {list_res.get('mess', 'Lỗi không xác định')}")
                            return None
                        state.provinces = [p for p in list_res["data"]["list"]]
                        logger.info(f"{username}: Lấy được {len(state.provinces)} tỉnh")
                    except (ClientConnectionError, ServerDisconnectedError, ProxyError) as e:
                        logger.warning(f"{username}: Lỗi mạng khi lấy danh sách tỉnh: {str(e)} (thử lần {retry + 1}/{MAX_SESSION_RETRIES})")
                        await asyncio.sleep(RETRY_DELAY)
                        return await send_wish(session, retry + 1)
                    except Exception as e:
                        logger.error(f"{username}: Lỗi không mong muốn khi lấy danh sách tỉnh: {str(e)} (thử lần {retry + 1}/{MAX_SESSION_RETRIES})")
                        await asyncio.sleep(RETRY_DELAY)
                        return await send_wish(session, retry + 1)

                if not state.provinces:
                    logger.warning(f"{username}: Không có tỉnh nào để gửi lời chúc")
                    return None

                import random
                selected = random.choice(state.provinces)
                logger.info(f"{username}: Chọn tỉnh: {selected['ProvinceName']} (ID: {selected['ProvinceID']})")

                wish_time = get_current_timestamp()
                wish_sign = await generate_sign(wish_time, "wish-send")
                wish_payload = {
                    "time": wish_time,
                    "fromIP": "",
                    "sign": wish_sign,
                    "makerCode": MAKER_CODE,
                    "func": "wish-send",
                    "data": {
                        "FullName": state.account_nick or username,
                        "Avatar": selected["Avatar"],
                        "ProvinceID": selected["ProvinceID"],
                        "ProvinceName": selected["ProvinceName"],
                        "Content": "Chúc sự kiện thành công!"
                    }
                }
                try:
                    async with session.post(API_URL, json=wish_payload, headers=mission_headers, ssl=True) as response:
                        wish_res = await response.json()
                    await asyncio.sleep(1)
                    if wish_res.get("mess") != "Gửi lời chúc thành công!":
                        logger.warning(f"{username}: Không gửi được lời chúc: {wish_res.get('mess', 'Lỗi không xác định')}")
                        return None
                    log_id = wish_res.get("code")
                    logger.info(f"{username}: Gửi lời chúc thành công, LogID: {log_id}")
                    return log_id, wish_time
                except (ClientConnectionError, ServerDisconnectedError, ProxyError) as e:
                    logger.warning(f"{username}: Lỗi mạng khi gửi lời chúc: {str(e)} (thử lần {retry + 1}/{MAX_SESSION_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await send_wish(session, retry + 1)
                except Exception as e:
                    logger.error(f"{username}: Lỗi không mong muốn khi gửi lời chúc: {str(e)} (thử lần {retry + 1}/{MAX_SESSION_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await send_wish(session, retry + 1)

            async def perform_share(session: ClientSession, wish_time: int, log_id: int, retry: int = 0) -> bool:
                if retry >= MAX_SESSION_RETRIES:
                    logger.warning(f"{username}: Không chia sẻ được sau {MAX_SESSION_RETRIES} lần thử")
                    return False

                share_time = wish_time
                share_raw = f"{share_time}{MAKER_CODE}{AU_URL}{BACKEND_KEY_SIGN}"
                share_sign = hashlib.sha256(share_raw.encode('utf-8')).hexdigest()
                share_url = f"{AU_URL}/bsau/api/generate-share-token?username={username}&time={share_time}&sign={share_sign}"
                api_headers = {
                    "User-Agent": mission_headers["User-Agent"],
                    "Accept": "application/json",
                    "Referer": AU_URL,
                }
                try:
                    async with session.get(share_url, headers=api_headers, ssl=True) as response:
                        content_type = response.headers.get('Content-Type', '')
                        if 'application/json' not in content_type:
                            logger.warning(f"{username}: Phản hồi không phải JSON từ API token chia sẻ: Content-Type={content_type}")
                            await asyncio.sleep(RETRY_DELAY)
                            return await perform_share(session, wish_time, log_id, retry + 1)
                        share_res = await response.json()
                    await asyncio.sleep(1)
                    share_token = share_res.get("token")
                    if not share_token:
                        logger.warning(f"{username}: Không nhận được token chia sẻ: {share_res}")
                        await asyncio.sleep(RETRY_DELAY)
                        return await perform_share(session, wish_time, log_id, retry + 1)
                    logger.info(f"{username}: Lấy được token chia sẻ: {share_token}")

                    final_time = get_current_timestamp()
                    final_sign = await generate_sign(final_time, "wish-share")
                    share_payload = {
                        "time": final_time,
                        "fromIP": "",
                        "sign": final_sign,
                        "makerCode": MAKER_CODE,
                        "func": "wish-share",
                        "data": {
                            "LogID": log_id,
                            "key": share_token,
                            "timestamp": share_time,
                            "a": "aa"
                        }
                    }
                    async with session.post(API_URL, json=share_payload, headers=mission_headers, ssl=True) as response:
                        share_send_res = await response.json()
                    await asyncio.sleep(1)
                    if share_send_res.get("code") == 1:
                        logger.info(f"{username}: Chia sẻ thành công")
                        return True
                    elif share_send_res.get("mess") == "Chữ ký không hợp lệ":
                        logger.warning(f"{username}: Chữ ký không hợp lệ (thử lần {retry + 1}/{MAX_SESSION_RETRIES})")
                        await asyncio.sleep(RETRY_DELAY)
                        return await perform_share(session, wish_time, log_id, retry + 1)
                    else:
                        logger.warning(f"{username}: Chia sẻ thất bại: {share_send_res.get('mess', 'Lỗi không xác định')}")
                        return False
                except (ClientConnectionError, ServerDisconnectedError, ProxyError) as e:
                    logger.warning(f"{username}: Lỗi mạng khi chia sẻ: {str(e)} (thử lần {retry + 1}/{MAX_SESSION_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await perform_share(session, wish_time, log_id, retry + 1)
                except Exception as e:
                    logger.error(f"{username}: Lỗi không mong muốn khi chia sẻ: {str(e)} (thử lần {retry + 1}/{MAX_SESSION_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await perform_share(session, wish_time, log_id, retry + 1)

            state.account_nick = username
            logger.info(f"{username}: Thực hiện chia sẻ lần {state.share_count + 1}")
            result = await send_wish(session)
            if result:
                log_id, wish_time = result
                if await perform_share(session, wish_time, log_id):
                    state.share_count += 1
                    logger.info(f"{username}: Hoàn thành chia sẻ lần {state.share_count}")
                    return True
                else:
                    logger.warning(f"{username}: Hành động chia sẻ thất bại")
                    return False
            else:
                logger.warning(f"{username}: Không lấy được LogID để chia sẻ")
                return False

        except Exception as err:
            logger.error(f"{username}: Lỗi không mong muốn trong quy trình chia sẻ: {str(err)}")
            return False

async def load_accounts() -> List[Tuple[str, str]]:
    """Tải danh sách tài khoản từ file."""
    try:
        with open(FILE_NAME, 'r', encoding='utf-8') as f:
            return [line.strip().split('|') for line in f if line.strip()]
    except Exception as err:
        logger.error(f"Lỗi khi đọc file tài khoản: {str(err)}")
        return []

async def process_account(session: ClientSession, username: str, key: str, state: AccountState, semaphore: asyncio.Semaphore) -> None:
    """Xử lý một tài khoản, luôn retry cho đến khi thành công."""
    async with semaphore:
        logger.info(f"Bắt đầu xử lý tài khoản: {username}")

        key_decoded = None
        token = None
        success = False

        # Decode key (retry nếu lỗi ValueError)
        while key_decoded is None:
            try:
                key_decoded = bytes.fromhex(key).decode('utf-8')
                logger.info(f"{username}: Giải mã key thành công")
            except ValueError as e:
                logger.error(f"{username}: Định dạng khóa không hợp lệ: {str(e)} → thử lại")
                await asyncio.sleep(1)

        # Lấy token (retry vô hạn đến khi có token)
        attempt = 0
        while not token:
            attempt += 1
            try:
                token = await get_token(key_decoded, username)
                if token:
                    logger.info(f"{username}: Lấy token thành công (lần {attempt})")
                    break
                else:
                    logger.warning(f"{username}: Token rỗng, thử lại (lần {attempt})")
            except Exception as e:
                logger.warning(f"{username}: Lỗi khi lấy token (lần {attempt}): {str(e)}")
            await asyncio.sleep(1)

        # Chia sẻ (retry vô hạn đến khi thành công)
        share_attempt = 0
        while not success:
            share_attempt += 1
            try:
                success = await share_event_flow(username, token, state)
                if success:
                    logger.info(f"{username}: Chia sẻ thành công (lần {share_attempt}), hoàn thành lượt xử lý")
                    break
                else:
                    logger.warning(f"{username}: Chia sẻ thất bại, thử lại (lần {share_attempt})")
            except Exception as e:
                logger.warning(f"{username}: Lỗi khi chia sẻ (lần {share_attempt}): {str(e)}")
            await asyncio.sleep(1)

        logger.info(f"Hoàn thành xử lý tài khoản: {username}")


async def main():
    """Hàm chính để xử lý tất cả tài khoản."""
    while True:  # Vòng lặp vô hạn để chạy lại toàn bộ tài khoản
        accounts = await load_accounts()
        if not accounts:
            logger.error("Không tìm thấy tài khoản hợp lệ trong file accounts.txt")
            return

        
        async with ClientSession(timeout=ClientTimeout(total=TIMEOUT)) as session:
            states = {username: AccountState() for username, _ in accounts}
            semaphore = asyncio.Semaphore(2)  # Giới hạn 2 tài khoản đồng thời

            for i in range(0, len(accounts), 2):
                batch = accounts[i:i+2]
                logger.info(f"Xử lý nhóm tài khoản từ {i+1} đến {i+len(batch)}")
                tasks = [
                    process_account(session, username, key, states[username], semaphore)
                    for username, key in batch
                ]
                await asyncio.gather(*tasks)
                logger.info(f"Hoàn thành nhóm tài khoản từ {i+1} đến {i+len(batch)}")
                await asyncio.sleep(3)  # Chờ 3 giây giữa các nhóm

            logger.info("Đã xử lý xong tất cả tài khoản, bắt đầu lại sau 10 giây")
            await asyncio.sleep(10)  # Chờ trước khi chạy lại toàn bộ tài khoản

if __name__ == "__main__":
    asyncio.run(main())