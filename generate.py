import requests
import base64
import socket
import time
import threading
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES_FILE = "sources.txt"
OUTPUT_TXT = "Molestunnels.txt"
OUTPUT_BASE64 = "Molestunnels_base64.txt"

MAX_SERVERS = 3000
MAX_PING = 1000
MAX_WORKERS = 200
DOWNLOAD_WORKERS = 20

HEADER = """#profile-title:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#subscription-userinfo: upload=0; download=0; total=0; expire=0
#profile-update-interval: 1
#support-url:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#profile-web-page-url:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#announce:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
"""

stop_event = threading.Event()
country_cache = {}
cache_lock = threading.Lock()


def read_sources():
    try:
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []


def download(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            return r.text.strip()
    except:
        pass
    return ""


def try_decode_base64(text):
    try:
        decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
        if "vless://" in decoded:
            return decoded
    except:
        pass
    return text


def extract_vless(text):
    text = try_decode_base64(text)
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("vless://")
    ]


def get_host_port(vless_link):
    try:
        parsed = urlparse(vless_link)
        return parsed.hostname, parsed.port or 443
    except:
        return None, None


def get_country_info(ip):
    with cache_lock:
        if ip in country_cache:
            return country_cache[ip]

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode",
            timeout=5,
        )
        data = r.json()
        if data.get("countryCode"):
            flag = chr(127397 + ord(data["countryCode"][0])) + chr(
                127397 + ord(data["countryCode"][1])
            )
            result = (flag, data["country"])
        else:
            result = ("🏳", "UNKNOWN")
    except:
        result = ("🏳", "UNKNOWN")

    with cache_lock:
        country_cache[ip] = result

    return result


def ping_server(server):
    if stop_event.is_set():
        return None

    host, port = get_host_port(server)
    if not host:
        return None

    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=3)
        sock.close()
        ping = int((time.time() - start) * 1000)

        if ping <= MAX_PING:
            flag, country = get_country_info(host)
            return (server, ping, flag, country)

    except:
        return None

    return None


def rename_server(server, index, flag, country):
    parsed = urlparse(server)
    new_name = f"{flag} {country} | KPOT-{index:04d}"
    return urlunparse(parsed._replace(fragment=new_name))


def main():
    urls = read_sources()

    # 🔥 Параллельная загрузка sources
    all_servers = []
    with ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        futures = [executor.submit(download, url) for url in urls]
        for future in as_completed(futures):
            content = future.result()
            if content:
                all_servers.extend(extract_vless(content))

    unique_servers = list(set(all_servers))
    print(f"Найдено VLESS: {len(unique_servers)}")

    valid_servers = []

    # 🚀 Параллельный пинг
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(ping_server, s): s for s in unique_servers}

        for future in as_completed(futures):
            if stop_event.is_set():
                break

            result = future.result()
            if result:
                valid_servers.append(result)

                if len(valid_servers) >= MAX_SERVERS:
                    stop_event.set()
                    executor.shutdown(cancel_futures=True)
                    break

    valid_servers.sort(key=lambda x: x[1])

    final_servers = []
    for i, (server, ping, flag, country) in enumerate(
        valid_servers[:MAX_SERVERS], 1
    ):
        final_servers.append(rename_server(server, i, flag, country))

    print(f"Оставлено: {len(final_servers)}")

    if final_servers:
        full_text = HEADER + "\n" + "\n".join(final_servers)
    else:
        full_text = HEADER

    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write(full_text)

    encoded = base64.b64encode(full_text.encode("utf-8")).decode("utf-8")

    with open(OUTPUT_BASE64, "w", encoding="utf-8") as f:
        f.write(encoded)

    print("Готово 🚀")


if __name__ == "__main__":
    main()
