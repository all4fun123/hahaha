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

# Configuration (replace with environment variables or config file in production)
CONFIGPROXY = 'http://103.67.199.104:20051/'  # Proxy URL, e.g., socks5://user:pass@host:port
FILE_NAME = 'account.txt'
TIMEOUT = 10  # seconds
MAX_TOKEN_RETRIES = 20
MAX_SESSION_RETRIES = 20
RETRY_DELAY = 1  # seconds
API_URL = "https://apiwebevent.vtcgame.vn/besnau19/Event"
MAKER_CODE = "BEAuSN19"
BACKEND_KEY_SIGN = "de54c591d457ed1f1769dda0013c9d30f6fc9bbff0b36ea0a425233bd82a1a22"
AU_URL = "https://au.vtc.vn"
MAX_SHARES = 30  # Maximum shares per account

# Logging setup
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
    """Fetch authentication token for the given account."""
    if retry >= MAX_TOKEN_RETRIES:
        logger.error(f"{account}: Failed to get token after {MAX_TOKEN_RETRIES} retries")
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
            # Login request
            async with session.post(
                'https://au.vtc.vn/header/Handler/Process.ashx?act=GetCookieAuthString',
                data=f'info={quote(key)}',
                ssl=True
            ) as response:
                if response.status != 200:
                    logger.warning(f"{account}: Login failed, status code: {response.status} (retry {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)
                try:
                    data = await response.json()
                except aiohttp.ContentTypeError:
                    logger.warning(f"{account}: Invalid JSON response during login (retry {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)
                if data.get('ResponseStatus') != 1:
                    logger.warning(f"{account}: Login failed: {data.get('ResponseMessage', 'No message')} (retry {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)
                logger.info(f"{account}: Login successful")

            # Fetch token from auparty page
            async with session.get('https://au.vtc.vn/auparty', ssl=True) as response:
                if response.status != 200:
                    logger.warning(f"{account}: Failed to access auparty page, status: {response.status} (retry {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)
                data = await response.text()
                match = re.search(r'\\"tokenValue\\":\\"(.*?)\\"', data)
                if match:
                    token_value = match.group(1)
                    logger.info(f"{account}: Successfully extracted token")
                    return token_value
                else:
                    logger.warning(f"{account}: Could not extract tokenValue (retry {retry + 1}/{MAX_TOKEN_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await get_token(key, account, retry + 1)

        except (ClientConnectionError, ServerDisconnectedError) as e:
            logger.warning(f"{account}: Network error while fetching token: {str(e)} (retry {retry + 1}/{MAX_TOKEN_RETRIES})")
            await asyncio.sleep(RETRY_DELAY)
            return await get_token(key, account, retry + 1)
        except Exception as e:
            logger.error(f"{account}: Unexpected error while fetching token: {str(e)} (retry {retry + 1}/{MAX_TOKEN_RETRIES})")
            await asyncio.sleep(RETRY_DELAY)
            return await get_token(key, account, retry + 1)

async def share_event_flow(username: str, bearer_token: str, state: AccountState) -> bool:
    """Perform the share event flow for the account."""
    connector = ProxyConnector.from_url(CONFIGPROXY) if CONFIGPROXY else None
    async with ClientSession(connector=connector, timeout=ClientTimeout(total=TIMEOUT)) as session:
        try:
            # Check proxy if configured
            if CONFIGPROXY:
                for retry in range(3):
                    try:
                        async with session.get('http://ip-api.com/json', ssl=True, timeout=ClientTimeout(total=TIMEOUT)) as response:
                            if response.status == 200:
                                data = await response.json()
                                logger.info(f"Proxy working: IP {data.get('query', 'unknown')}, Country: {data.get('country', 'unknown')}")
                                break
                            else:
                                logger.warning(f"{username}: Proxy check failed, status: {response.status} (retry {retry + 1}/3)")
                                if retry < 2:
                                    await asyncio.sleep(RETRY_DELAY)
                                continue
                    except (ClientConnectionError, ServerDisconnectedError, ProxyError) as e:
                        logger.warning(f"{username}: Proxy network error: {str(e)} (retry {retry + 1}/3)")
                        if retry < 2:
                            await asyncio.sleep(RETRY_DELAY)
                        continue
                    except Exception as e:
                        logger.error(f"{username}: Unexpected error during proxy check: {str(e)} (retry {retry + 1}/3)")
                        if retry < 2:
                            await asyncio.sleep(RETRY_DELAY)
                        continue
                else:
                    logger.error(f"{username}: Proxy unusable after 3 retries")
                    return False

            def get_current_timestamp() -> int:
                """Get current timestamp in seconds."""
                return int(time.time())

            async def generate_sign(time: int, func: str) -> str:
                """Generate SHA256 signature for API requests."""
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
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
                "Referer": AU_URL
            }

            async def send_wish(session: ClientSession, retry: int = 0) -> Optional[int]:
                """Send a wish to get a LogID."""
                if retry >= MAX_SESSION_RETRIES:
                    logger.warning(f"{username}: Failed to send wish after {MAX_SESSION_RETRIES} retries")
                    return None

                if not state.provinces:
                    logger.info(f"{username}: Fetching province list...")
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
                        await asyncio.sleep(0.5)
                        if list_res.get("code") != 1:
                            logger.warning(f"{username}: Failed to fetch province list: {list_res.get('mess', 'Unknown error')}")
                            return None
                        state.provinces = [p for p in list_res["data"]["list"]]
                        logger.info(f"{username}: Fetched {len(state.provinces)} provinces")
                    except (ClientConnectionError, ServerDisconnectedError, ProxyError) as e:
                        logger.warning(f"{username}: Network error fetching province list: {str(e)} (retry {retry + 1}/{MAX_SESSION_RETRIES})")
                        await asyncio.sleep(RETRY_DELAY)
                        return await send_wish(session, retry + 1)
                    except Exception as e:
                        logger.error(f"{username}: Unexpected error fetching province list: {str(e)} (retry {retry + 1}/{MAX_SESSION_RETRIES})")
                        await asyncio.sleep(RETRY_DELAY)
                        return await send_wish(session, retry + 1)

                if not state.provinces:
                    logger.warning(f"{username}: No provinces available to send wish")
                    return None

                import random
                selected = random.choice(state.provinces)
                logger.info(f"{username}: Selected province: {selected['ProvinceName']} (ID: {selected['ProvinceID']})")

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
                    await asyncio.sleep(0.5)
                    if wish_res.get("mess") != "Gửi lời chúc thành công!":
                        logger.warning(f"{username}: Failed to send wish: {wish_res.get('mess', 'Unknown error')}")
                        return None
                    log_id = wish_res.get("code")
                    logger.info(f"{username}: Wish sent successfully, LogID: {log_id}")
                    return log_id
                except (ClientConnectionError, ServerDisconnectedError, ProxyError) as e:
                    logger.warning(f"{username}: Network error sending wish: {str(e)} (retry {retry + 1}/{MAX_SESSION_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await send_wish(session, retry + 1)
                except Exception as e:
                    logger.error(f"{username}: Unexpected error sending wish: {str(e)} (retry {retry + 1}/{MAX_SESSION_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await send_wish(session, retry + 1)

            async def perform_share(session: ClientSession, log_id: int, retry: int = 0) -> bool:
                """Perform the share action using the LogID."""
                if retry >= MAX_SESSION_RETRIES:
                    logger.warning(f"{username}: Failed to perform share after {MAX_SESSION_RETRIES} retries")
                    return False

                share_time = get_current_timestamp()
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
                            logger.warning(f"{username}: Non-JSON response from share token API: Content-Type={content_type}")
                            await asyncio.sleep(RETRY_DELAY)
                            return await perform_share(session, log_id, retry + 1)
                        share_res = await response.json()
                    await asyncio.sleep(0.5)
                    share_token = share_res.get("token")
                    if not share_token:
                        logger.warning(f"{username}: No share token received: {share_res}")
                        await asyncio.sleep(RETRY_DELAY)
                        return await perform_share(session, log_id, retry + 1)
                    logger.info(f"{username}: Retrieved share token: {share_token}")

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
                            "timestamp": final_time,
                            "a": "aa"
                        }
                    }
                    async with session.post(API_URL, json=share_payload, headers=mission_headers, ssl=True) as response:
                        share_send_res = await response.json()
                    await asyncio.sleep(0.5)
                    if share_send_res.get("code") == 1:
                        logger.info(f"{username}: Share successful")
                        return True
                    elif share_send_res.get("mess") == "Chữ ký không hợp lệ":
                        logger.warning(f"{username}: Invalid signature (retry {retry + 1}/{MAX_SESSION_RETRIES})")
                        await asyncio.sleep(RETRY_DELAY)
                        return await perform_share(session, log_id, retry + 1)
                    else:
                        logger.warning(f"{username}: Share failed: {share_send_res.get('mess', 'Unknown error')}")
                        return False
                except (ClientConnectionError, ServerDisconnectedError, ProxyError) as e:
                    logger.warning(f"{username}: Network error during share: {str(e)} (retry {retry + 1}/{MAX_SESSION_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await perform_share(session, log_id, retry + 1)
                except Exception as e:
                    logger.error(f"{username}: Unexpected error during share: {str(e)} (retry {retry + 1}/{MAX_SESSION_RETRIES})")
                    await asyncio.sleep(RETRY_DELAY)
                    return await perform_share(session, log_id, retry + 1)

            state.account_nick = username
            if state.share_count >= MAX_SHARES:
                logger.info(f"{username}: Reached share limit ({state.share_count}/{MAX_SHARES})")
                return False

            logger.info(f"{username}: Performing share {state.share_count + 1}/{MAX_SHARES}")
            log_id = await send_wish(session)
            if log_id:
                if await perform_share(session, log_id):
                    state.share_count += 1
                    logger.info(f"{username}: Completed share {state.share_count}/{MAX_SHARES}")
                    return True
                else:
                    logger.warning(f"{username}: Share action failed")
                    return False
            else:
                logger.warning(f"{username}: Failed to obtain LogID for sharing")
                return False

        except Exception as err:
            logger.error(f"{username}: Unexpected error in share event flow: {str(err)}")
            return False

async def load_accounts() -> List[Tuple[str, str]]:
    """Load accounts from file."""
    try:
        with open(FILE_NAME, 'r', encoding='utf-8') as f:
            return [line.strip().split('|') for line in f if line.strip()]
    except Exception as err:
        logger.error(f"Error reading accounts file: {str(err)}")
        return []

async def process_account(session: ClientSession, username: str, key: str, state: AccountState, semaphore: asyncio.Semaphore) -> None:
    """Process a single account."""
    async with semaphore:
        logger.info(f"Starting processing for account: {username}")
        try:
            key_decoded = bytes.fromhex(key).decode('utf-8')
            token = await get_token(key_decoded, username)
            if not token:
                logger.error(f"{username}: Skipping due to token retrieval failure")
                return

            while state.share_count < MAX_SHARES:
                success = await share_event_flow(username, token, state)
                if success:
                    logger.info(f"{username}: Share successful, waiting 3 seconds")
                    await asyncio.sleep(3)
                else:
                    logger.warning(f"{username}: Share failed, retrying after 5 seconds")
                    await asyncio.sleep(5)
            logger.info(f"{username}: Completed {state.share_count}/{MAX_SHARES} shares")

        except ValueError as e:
            logger.error(f"{username}: Invalid key format: {str(e)}")
        except Exception as e:
            logger.error(f"{username}: Error processing account: {str(e)}")
        logger.info(f"Finished processing account: {username}")

async def main():
    """Main function to process all accounts."""
    accounts = await load_accounts()
    if not accounts:
        logger.error("No valid accounts found in accounts.txt")
        return

    connector = ProxyConnector.from_url(CONFIGPROXY) if CONFIGPROXY else None
    async with ClientSession(connector=connector, timeout=ClientTimeout(total=TIMEOUT)) as session:
        states = {username: AccountState() for username, _ in accounts}
        semaphore = asyncio.Semaphore(2)  # Limit to 5 concurrent accounts

        # Process accounts in batches of 5
        for i in range(0, len(accounts), 2):
            batch = accounts[i:i+2]
            logger.info(f"Processing account batch {i+1} to {i+len(batch)}")
            tasks = [
                process_account(session, username, key, states[username], semaphore)
                for username, key in batch
            ]
            await asyncio.gather(*tasks)
            logger.info(f"Completed account batch {i+1} to {i+len(batch)}")

        logger.info("All accounts processed")

if __name__ == "__main__":
    asyncio.run(main())