#!/usr/bin/env python3
# GENERATOR.py – Максимально быстрая проверка Vless/SS/Trojan серверов + флаги стран (эмодзи)
# Версия с поддержкой часового пояса для даты в подписке

import re
import socket
import base64
import logging
import subprocess
import time
import json
import tempfile
import os
import sys
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime

# ---------- НАСТРОЙКА ЛОГИРОВАНИЯ (ВЫВОД В STDOUT, СБРОС ПОСЛЕ КАЖДОЙ ЗАПИСИ) ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # <-- теперь логи идут в stdout
    ],
    force=True  # переопределяет предыдущие настройки
)

# Попытка импорта zoneinfo для локального времени
try:
    from zoneinfo import ZoneInfo
    TIMEZONE = "Asia/Yekaterinburg"  # ⬅️ измените на свой (например, Europe/Moscow)
    LOCAL_NOW = datetime.now(ZoneInfo(TIMEZONE))
    logging.info(f"🕐 Используется часовой пояс: {TIMEZONE}")
except ImportError:
    LOCAL_NOW = datetime.utcnow()
    logging.warning("⚠️ Библиотека zoneinfo не найдена, используется UTC для даты в подписке.")
TODAY_STR = LOCAL_NOW.strftime("%d-%m-%Y")

import requests

# Попытка импорта geoip2 (для флагов стран)
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logging.warning("⚠️ Библиотека 'geoip2' не установлена. Флаги стран не будут добавлены. Установите: pip install geoip2")

# ---------- Константы для оформления подписки ----------
PROFILE_TITLE = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
SUPPORT_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
PROFILE_WEB_PAGE_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
PROFILE_UPDATE_INTERVAL = "1"
SUBSCRIPTION_USERINFO = "upload=0; download=0; total=0; expire=0"

# ---------- Основные константы ----------
SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "subscription.txt"
OUTPUT_BASE64_FILE = "subscription_base64.txt"
REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
XRAY_CORE_PATH = "xray"

# Ускоренная TCP-проверка
TCP_CHECK_TIMEOUT = 2
TCP_MAX_WORKERS = 400

# Реальная проверка
SOCKS_PORT = 8080
REAL_CHECK_TIMEOUT = 12
REAL_CHECK_CONCURRENCY = 9
XRAY_STARTUP_DELAY = 2
RETRY_COUNT = 0

TEST_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204"
]

MAX_LATENCY_MS = 500   # 0.5 секунды
ONLY_TCP = False

# ---------- GeoIP ----------
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
GEOIP_DB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"

def ensure_geoip_db():
    """Скачивает базу GeoIP, если её нет."""
    if not GEOIP_AVAILABLE:
        return False
    if os.path.exists(GEOIP_DB_PATH):
        return True
    logging.info("🌍 База GeoIP не найдена. Пытаемся скачать...")
    try:
        r = requests.get(GEOIP_DB_URL, timeout=30)
        r.raise_for_status()
        with open(GEOIP_DB_PATH, 'wb') as f:
            f.write(r.content)
        logging.info(f"✅ База GeoIP скачана: {GEOIP_DB_PATH}")
        return True
    except Exception as e:
        logging.error(f"❌ Не удалось скачать базу GeoIP: {e}")
        return False

# Инициализация reader'а GeoIP
reader = None
if ensure_geoip_db():
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception as e:
        logging.error(f"❌ Не удалось открыть базу GeoIP: {e}")
        reader = None

def get_country_flag(ip):
    """Возвращает эмодзи-флаг по IP (или пустую строку)."""
    if reader is None:
        return ""
    try:
        response = reader.country(ip)
        country_code = response.country.iso_code
        if country_code:
            # Конвертируем код (RU, US) в региональные символы 🇷🇺, 🇺🇸
            return ''.join(chr(127397 + ord(c)) for c in country_code.upper())
    except Exception:
        pass
    return ""

# ---------- Вспомогательные функции ----------
@lru_cache(maxsize=256)
def resolve_host(host):
    """Кэширует IP-адрес по имени хоста."""
    return socket.gethostbyname(host)

def read_sources():
    logging.info("📖 Чтение файла sources.txt...")
    sources = []
    try:
        with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    sources.append(line)
        logging.info(f"📚 Загружено {len(sources)} источников")
    except FileNotFoundError:
        logging.error(f"❌ Файл {SOURCES_FILE} не найден")
    return sources

def fetch_content(url):
    logging.info(f"⬇️ Загружаю источник: {url}")
    try:
        headers = {'User-Agent': USER_AGENT}
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        resp.raise_for_status()
        logging.info(f"✅ Загружено {len(resp.text)} байт из {url}")
        return resp.text
    except Exception as e:
        logging.warning(f"⚠️ Не удалось загрузить {url}: {e}")
        return None

def extract_links_from_text(text):
    """Извлекает ссылки Vless, Shadowsocks и Trojan."""
    return re.findall(r'(?:vless|ss|trojan)://[^\s<>"\']+', text)

def decode_base64_content(encoded):
    try:
        encoded = encoded.strip()
        decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
        return decoded
    except:
        return encoded

def gather_all_links(sources):
    logging.info(f"🔍 Начинаю сбор ссылок из {len(sources)} источников...")
    all_links = set()
    for idx, src in enumerate(sources, 1):
        logging.info(f"📦 Обработка источника [{idx}/{len(sources)}]: {src[:60]}...")
        if src.startswith(('vless://', 'ss://', 'trojan://')):
            all_links.add(src)
            continue

        content = fetch_content(src)
        if not content:
            continue

        decoded = decode_base64_content(content)
        links = extract_links_from_text(content)
        if decoded != content:
            links.extend(extract_links_from_text(decoded))

        for link in links:
            all_links.add(link)

        logging.info(f"🔗 Из {src} получено {len(links)} ссылок")

    logging.info(f"🎯 Всего собрано уникальных ссылок: {len(all_links)}")
    return list(all_links)

# ---------- Парсеры для разных протоколов ----------
def parse_vless_link(link):
    try:
        without_proto = link[8:]
        at_index = without_proto.find('@')
        if at_index == -1:
            return None

        uuid = without_proto[:at_index]
        rest = without_proto[at_index+1:]

        parsed = urlparse(f"tcp://{rest}")
        host = parsed.hostname
        port = parsed.port or 443

        params = parse_qs(parsed.query)
        security = params.get('security', ['none'])[0]
        if security == 'tsl':
            security = 'tls'

        # Явно указанный SNI (если есть)
        explicit_sni = params.get('sni', [None])[0]

        config = {
            'protocol': 'vless',
            'uuid': uuid,
            'host': host,
            'port': port,
            'security': security,
            'encryption': params.get('encryption', ['none'])[0],
            'type': params.get('type', ['tcp'])[0],
            # Для Xray всегда нужно значение sni (явное или host)
            'sni': explicit_sni if explicit_sni else host,
            # Явный SNI для тега
            'explicit_sni': explicit_sni,
            'fp': params.get('fp', ['chrome'])[0],
            'pbk': params.get('pbk', [''])[0],
            'sid': params.get('sid', [''])[0],
            'spx': params.get('spx', ['/'])[0],
            'flow': params.get('flow', [''])[0],
            'path': params.get('path', ['/'])[0],
            'host_header': params.get('host', [host])[0]
        }
        return config
    except Exception as e:
        logging.debug(f"Ошибка парсинга Vless-ссылки {link[:50]}...: {e}")
        return None

def parse_ss_link(link):
    """Парсит ссылку Shadowsocks (ss://)."""
    try:
        # удаляем 'ss://'
        rest = link[5:]
        # отделяем параметры по '?' и '#'
        if '#' in rest:
            rest, _ = rest.split('#', 1)
        if '?' in rest:
            rest, _ = rest.split('?', 1)

        # теперь rest содержит либо base64, либо userinfo@hostport
        if '@' in rest:
            # формат userinfo@hostport
            userinfo, hostport = rest.split('@', 1)
            # userinfo: method:password
            if ':' in userinfo:
                method, password = userinfo.split(':', 1)
            else:
                return None
        else:
            # вероятно base64
            try:
                decoded = base64.b64decode(rest).decode('utf-8')
                if '@' in decoded:
                    userinfo, hostport = decoded.split('@', 1)
                    if ':' in userinfo:
                        method, password = userinfo.split(':', 1)
                    else:
                        return None
                else:
                    return None
            except:
                return None

        # hostport вида host:port
        if ':' in hostport:
            host, port_str = hostport.rsplit(':', 1)
            try:
                port = int(port_str)
            except:
                return None
        else:
            port = 443  # на всякий случай, хотя обычно порт указывается

        return {
            'protocol': 'ss',
            'host': host,
            'port': port,
            'method': method,
            'password': password,
            'original': link,
            'explicit_sni': None   # у Shadowsocks нет SNI
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга SS-ссылки {link[:50]}...: {e}")
        return None

def parse_trojan_link(link):
    """Парсит ссылку Trojan (trojan://)."""
    try:
        parsed = urlparse(link)
        if parsed.scheme != 'trojan':
            return None
        userinfo = parsed.username
        if not userinfo:
            return None
        password = userinfo
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)

        # Явный SNI (peer или sni)
        peer_param = params.get('peer')
        sni_param = params.get('sni')
        explicit_sni = None
        if peer_param:
            explicit_sni = peer_param[0]
        elif sni_param:
            explicit_sni = sni_param[0]

        # Для совместимости оставляем поле sni (всегда заполнено)
        sni = explicit_sni if explicit_sni else host

        allow_insecure = params.get('allowInsecure', ['0'])[0].lower() in ('1', 'true', 'yes')
        network = params.get('type', ['tcp'])[0]
        security = params.get('security', ['tls'])[0]

        return {
            'protocol': 'trojan',
            'host': host,
            'port': port,
            'password': password,
            'sni': sni,
            'explicit_sni': explicit_sni,
            'allow_insecure': allow_insecure,
            'network': network,
            'security': security,
            'original': link
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга Trojan-ссылки {link[:50]}...: {e}")
        return None

def parse_link(link):
    """Универсальный парсер: определяет протокол и вызывает соответствующий парсер."""
    if link.startswith('vless://'):
        return parse_vless_link(link)
    elif link.startswith('ss://'):
        return parse_ss_link(link)
    elif link.startswith('trojan://'):
        return parse_trojan_link(link)
    else:
        return None

# ---------- Создание конфигурации Xray ----------
def create_xray_config(config):
    """Создаёт конфигурацию Xray на основе распарсенных параметров."""
    base_config = {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "port": SOCKS_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "ip": "127.0.0.1"
                }
            }
        ],
        "outbounds": []
    }

    protocol = config['protocol']
    if protocol == 'vless':
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": config['host'],
                        "port": config['port'],
                        "users": [
                            {
                                "id": config['uuid'],
                                "encryption": config.get('encryption', 'none'),
                                "flow": config.get('flow', '')
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": config.get('type', 'tcp'),
                "security": config.get('security', 'none')
            }
        }
        if config['security'] == 'tls':
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": config.get('sni', config['host']),
                "fingerprint": config.get('fp', 'chrome'),
                "allowInsecure": False
            }
        elif config['security'] == 'reality':
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": config.get('sni', config['host']),
                "fingerprint": config.get('fp', 'chrome'),
                "publicKey": config.get('pbk', ''),
                "shortId": config.get('sid', ''),
                "spiderX": config.get('spx', '/')
            }
        if config.get('type') == 'ws':
            outbound["streamSettings"]["wsSettings"] = {
                "path": config.get('path', '/'),
                "headers": {"Host": config.get('host_header', config['host'])}
            }
    elif protocol == 'ss':
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": config['host'],
                        "port": config['port'],
                        "method": config['method'],
                        "password": config['password']
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }
    elif protocol == 'trojan':
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": config['host'],
                        "port": config['port'],
                        "password": config['password']
                    }
                ]
            },
            "streamSettings": {
                "network": config.get('network', 'tcp'),
                "security": config.get('security', 'tls')
            }
        }
        if config.get('security') == 'tls':
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": config.get('sni', config['host']),
                "allowInsecure": config.get('allow_insecure', False)
            }
    else:
        return None

    base_config["outbounds"].append(outbound)
    return base_config

# ---------- Проверки ----------
def check_tcp(link):
    """Быстрая TCP-проверка доступности хоста и порта."""
    parsed = parse_link(link)
    if not parsed:
        return (link, False)
    host = parsed['host']
    port = parsed['port']
    try:
        ip = resolve_host(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_CHECK_TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return (link, result == 0)
    except Exception as e:
        logging.debug(f"TCP ошибка для {link[:60]}: {e}")
        return (link, False)

def check_real(link):
    """Реальная проверка через Xray-core (создание временного конфига и тестовый запрос)."""
    config_dict = parse_link(link)
    if not config_dict:
        return (link, False, None)

    xray_config = create_xray_config(config_dict)
    if not xray_config:
        return (link, False, None)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = f.name
        json.dump(xray_config, f, indent=2)

    process = None
    try:
        process = subprocess.Popen(
            [XRAY_CORE_PATH, 'run', '-config', config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        time.sleep(XRAY_STARTUP_DELAY)

        proxies = {
            'http': f'socks5h://127.0.0.1:{SOCKS_PORT}',
            'https': f'socks5h://127.0.0.1:{SOCKS_PORT}'
        }

        for test_url in TEST_URLS:
            try:
                start_time = time.time()
                response = requests.get(
                    test_url,
                    proxies=proxies,
                    timeout=REAL_CHECK_TIMEOUT,
                    headers={'User-Agent': USER_AGENT},
                    allow_redirects=False
                )
                latency = int((time.time() - start_time) * 1000)

                if response.status_code == 204:
                    return (link, True, latency)
                else:
                    logging.debug(f"URL {test_url} вернул {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.debug(f"Попытка для {test_url} не удалась: {e}")

        return (link, False, None)

    except Exception as e:
        logging.debug(f"Ошибка при проверке {link[:60]}...: {e}")
        return (link, False, None)
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if os.path.exists(config_path):
            os.unlink(config_path)

def filter_working_links(links):
    total = len(links)
    logging.info(f"🚀 Начинаю фильтрацию {total} ссылок")

    # Этап 1: TCP-проверка
    logging.info(f"🌐 Этап 1: TCP-проверка {total} ссылок (параллельность {TCP_MAX_WORKERS}, таймаут {TCP_CHECK_TIMEOUT}с)...")
    tcp_ok = []
    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        future_to_link = {executor.submit(check_tcp, link): link for link in links}
        for i, future in enumerate(as_completed(future_to_link), 1):
            link, ok = future.result()
            if ok:
                tcp_ok.append(link)
                logging.info(f"✅ TCP OK [{i}/{total}]: {link[:80]}...")
            else:
                logging.info(f"❌ TCP Failed [{i}/{total}]: {link[:80]}...")

    logging.info(f"📊 TCP-проверка завершена. Прошли: {len(tcp_ok)}/{total}")

    if ONLY_TCP:
        return tcp_ok

    if not tcp_ok:
        return []

    # Этап 2: реальная проверка
    logging.info(f"🧪 Этап 2: Реальная проверка {len(tcp_ok)} ссылок через Xray-core (порт {SOCKS_PORT}, параллельность {REAL_CHECK_CONCURRENCY})...")
    working_real = []
    too_slow = 0
    with ThreadPoolExecutor(max_workers=REAL_CHECK_CONCURRENCY) as executor:
        future_to_link = {executor.submit(check_real, link): link for link in tcp_ok}
        for i, future in enumerate(as_completed(future_to_link), 1):
            link, is_working, latency = future.result()
            if is_working:
                if MAX_LATENCY_MS > 0 and latency > MAX_LATENCY_MS:
                    too_slow += 1
                    logging.info(f"⚠️ [{i}/{len(tcp_ok)}] Слишком медленный (latency: {latency}ms > {MAX_LATENCY_MS}ms): {link[:80]}...")
                else:
                    working_real.append(link)
                    logging.info(f"✅ [{i}/{len(tcp_ok)}] Работает (latency: {latency}ms): {link[:80]}...")
            else:
                logging.info(f"❌ [{i}/{len(tcp_ok)}] Не работает: {link[:80]}...")

    if MAX_LATENCY_MS > 0 and too_slow > 0:
        logging.info(f"⚠️ Отсеяно по скорости: {too_slow} серверов с latency > {MAX_LATENCY_MS}ms")

    return working_real

def save_working_links(links):
    """
    Сохраняет рабочие ссылки в subscription.txt с красивыми заголовками.
    Каждая ссылка получает тег с номером, флагом страны, явным SNI (если есть) и датой.
    """
    logging.info(f"💾 Сохраняю {len(links)} рабочих ссылок в {OUTPUT_FILE}")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # Заголовки подписки
        f.write(f"#profile-title:{PROFILE_TITLE}\n")
        f.write(f"#subscription-userinfo:{SUBSCRIPTION_USERINFO}\n")
        f.write(f"#profile-update-interval:{PROFILE_UPDATE_INTERVAL}\n")
        f.write(f"#support-url:{SUPPORT_URL}\n")
        f.write(f"#profile-web-page-url:{PROFILE_WEB_PAGE_URL}\n")
        # Аннонс с эмодзи
        f.write(f"#announce: АКТИВНЫХ СЕРВЕРОВ 🚀 {len(links)} | ОБНОВЛЕНО 📅 {TODAY_STR}\n")

        # Сами ссылки с нумерацией и флагами
        for idx, link in enumerate(links, start=1):
            # Удаляем старые теги, если они были
            link = re.sub(r'#.*$', '', link)
            server_num = f"{idx:04d}"

            # Парсим ссылку для получения информации
            config = parse_link(link)
            flag = ""
            sni_part = None

            if config:
                # Получаем флаг страны по IP хоста
                try:
                    ip = resolve_host(config['host'])
                    flag = get_country_flag(ip)
                except Exception:
                    pass

                # Явно указанный SNI
                explicit_sni = config.get('explicit_sni')
                if explicit_sni:
                    sni_part = f"SNI- {explicit_sni}"

            # Формируем тег
            tag_parts = [f"#СЕРВЕР {server_num}"]
            if flag:
                tag_parts.append(flag)
            if sni_part:
                tag_parts.append(sni_part)
            tag_parts.append(f"ОБНОВЛЕН {TODAY_STR}")

            tag = " | ".join(tag_parts)

            f.write(link + tag + '\n')

    logging.info(f"💾 Сохранено {len(links)} рабочих ссылок в {OUTPUT_FILE} с заголовками и нумерацией.")

def create_base64_subscription():
    """Создаёт Base64-версию подписки."""
    try:
        with open(OUTPUT_FILE, 'rb') as f:
            content = f.read()
        encoded = base64.b64encode(content).decode('ascii')
        with open(OUTPUT_BASE64_FILE, 'w', encoding='ascii') as f:
            f.write(encoded)
        logging.info(f"💾 Сохранена Base64-версия подписки в {OUTPUT_BASE64_FILE}")
    except Exception as e:
        logging.error(f"❌ Ошибка при создании Base64-версии: {e}")

def check_xray_available():
    logging.info("🔍 Проверка наличия Xray-core...")
    try:
        result = subprocess.run([XRAY_CORE_PATH, '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logging.info(f"✅ Xray-core найден: {result.stdout.splitlines()[0]}")
            return True
        else:
            logging.warning("⚠️ Xray-core не отвечает")
            return False
    except FileNotFoundError:
        logging.error(f"❌ Xray-core не найден по пути '{XRAY_CORE_PATH}'")
        return False
    except Exception as e:
        logging.error(f"❌ Ошибка при проверке Xray-core: {e}")
        return False

def main():
    logging.info("🟢 Запуск генератора подписок")
    if not check_xray_available():
        logging.error("Xray-core обязателен. Завершение.")
        return

    sources = read_sources()
    if not sources:
        return

    all_links = gather_all_links(sources)
    if not all_links:
        return

    working_links = filter_working_links(all_links)
    save_working_links(working_links)

    if working_links:
        create_base64_subscription()
    else:
        logging.warning("Нет рабочих ссылок – Base64-версия не создана.")

    logging.info(f"📊 Итог: {len(working_links)} рабочих из {len(all_links)} проверенных")
    logging.info("🏁 Работа завершена")

if __name__ == "__main__":
    main()
