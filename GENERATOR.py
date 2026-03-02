import asyncio
import aiohttp
import base64
import socket
import re
from urllib.parse import urlparse
from datetime import datetime
from zoneinfo import ZoneInfo

INPUT_FILE = "sslist.txt"
OUTPUT_FILE = "Molestunnels.txt"
BASE64_FILE = "Molestunnels_base64.txt"

CONCURRENCY = 300
TIMEOUT = 1.5

PROFILE_TITLE = "📡КРОТовыеТОННЕЛИ📡"


def extract_vless(text):
    return list(set(re.findall(r'vless://[^\s]+', text)))


def country_to_flag(code):
    if not code or len(code) != 2:
        return "🌍"
    return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)


async def fetch_country(session, ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        async with session.get(url, timeout=2) as resp:
            data = await resp.json()
            return country_to_flag(data.get("countryCode"))
    except:
        return "🌍"


async def fetch(session, url):
    try:
        async with session.get(url, timeout=TIMEOUT) as response:
            return await response.text()
    except:
        return ""


async def check_once(host, port):
    try:
        future = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(future, timeout=TIMEOUT)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False


async def check_server(config, semaphore, session):
    try:
        parsed = urlparse(config)
        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            return None

        async with semaphore:
            first = await check_once(host, port)
            if not first:
                return None

            await asyncio.sleep(0.5)

            second = await check_once(host, port)
            if not second:
                return None

            ip = host
            try:
                ip = socket.gethostbyname(host)
            except:
                pass

            flag = await fetch_country(session, ip)

            clean_config = config.split("#")[0]
            return clean_config, flag

    except:
        return None


async def main():
    print("Reading sources...")

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            sources = [line.strip() for line in f if line.strip()]
    except:
        print("No sslist.txt found.")
        return

    async with aiohttp.ClientSession() as session:

        print("Fetching source contents...")
        tasks = [fetch(session, url) for url in sources]
        results = await asyncio.gather(*tasks)

        print("Extracting VLESS configs...")
        all_configs = []

        for text in results:
            all_configs.extend(extract_vless(text))

        all_configs = list(set(all_configs))
        print(f"Total unique VLESS configs: {len(all_configs)}")

        semaphore = asyncio.Semaphore(CONCURRENCY)

        print("Checking servers...")
        tasks = [check_server(cfg, semaphore, session) for cfg in all_configs]
        checked = await asyncio.gather(*tasks)

    alive = [c for c in checked if c is not None]

    print(f"Alive configs: {len(alive)}")

    if len(alive) == 0:
        print("WARNING: No alive configs found!")
        print("Abort overwrite to protect subscription.")
        exit(1)

    print("Sorting and numbering...")
    alive.sort(key=lambda x: x[0])

    # ===== МОСКОВСКАЯ ДАТА В ФОРМАТЕ 02-03-2026 =====
    moscow_time = datetime.now(ZoneInfo("Europe/Moscow"))
    update_date = moscow_time.strftime("%d-%m-%Y")

    # ===== HEADERS =====
    headers = [
        f"#profile-title:{PROFILE_TITLE}",
        "#subscription-userinfo: upload=0; download=0; total=0; expire=0",
        "#profile-update-interval: 1",
        f"#support-url:{PROFILE_TITLE}",
        f"#profile-web-page-url:{PROFILE_TITLE}",
        f"#announce: 🚀 АКТИВНО: {len(alive)} | 📅 {update_date}"
    ]

    final_lines = []

    for idx, (config, flag) in enumerate(alive, start=1):
        final_lines.append(
            f"{config}#{flag} СЕРВЕР {idx:03d} | ОБНОВЛЕН {update_date}"
        )

    print("Writing files...")

    final_text = "\n".join(headers + final_lines)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(final_text)

    base64_data = base64.b64encode(final_text.encode()).decode()

    with open(BASE64_FILE, "w", encoding="utf-8") as f:
        f.write(base64_data)

    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
