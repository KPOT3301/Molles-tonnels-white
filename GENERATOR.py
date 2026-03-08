#!/usr/bin/env python3
# GENERATOR.py – Проверка Vless/SS/Trojan/VMess/Hysteria2 серверов + флаги стран
# Добавлены протоколы VMess и Hysteria2, отсев по latency (> MAX_LATENCY_MS) сразу после TCP
# Логи TCP убраны, REAL_CHECK_CONCURRENCY = 30, XRAY_STARTUP_DELAY = 1, таймауты TCP=10с, Xray=15с
# Повторные проверки удалены: TCP_ATTEMPTS=1, RETRY_COUNT=0, HTTPS одна попытка
# Контроль задержки (≤500 мс) перенесён на этап TCP

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

# ---------- НАСТРОЙКА ЛОГИРОВАНИЯ ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)

# ---------- ГЛОБАЛЬНЫЕ СЧЁТЧИКИ ДЛЯ КОМПАКТНОГО ЛОГА ----------
record_counter = 0
current_check = 0
total_checks = 0

# ---------- ЧАСОВОЙ ПОЯС ----------
try:
    from zoneinfo import ZoneInfo
    TIMEZONE = "Asia/Yekaterinburg"
    LOCAL_NOW = datetime.now(ZoneInfo(TIMEZONE))
    logging.info(f"🕐 Используется часовой пояс: {TIMEZONE}")
except ImportError:
    LOCAL_NOW = datetime.utcnow()
    logging.warning("⚠️ Библиотека zoneinfo не найдена, используется UTC")
TODAY_STR = LOCAL_NOW.strftime("%d-%m-%Y")

import requests

# ---------- GEOIP ----------
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logging.warning("⚠️ Библиотека 'geoip2' не установлена. Флаги стран не будут добавлены.")

# ---------- КОНСТАНТЫ ПОДПИСКИ ----------
PROFILE_TITLE = "📡КРОТовыеТОННЕЛИ📡"
SUPPORT_URL = "📡КРОТовыеТОННЕЛИ📡"
PROFILE_WEB_PAGE_URL = "📡КРОТовыеТОННЕЛИ📡"
PROFILE_UPDATE_INTERVAL = "1"
SUBSCRIPTION_USERINFO = "upload=0; download=0; total=0; expire=0"

# ---------- ОСНОВНЫЕ КОНСТАНТЫ ----------
SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "subscription.txt"
OUTPUT_BASE64_FILE = "subscription_base64.txt"
REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
XRAY_CORE_PATH = "xray"

# TCP-проверка (таймаут 10 с, одна попытка)
TCP_CHECK_TIMEOUT = 10
TCP_MAX_WORKERS = 400
TCP_ATTEMPTS = 1          # только одна попытка TCP

# Реальная проверка
SOCKS_PORT = 8080
REAL_CHECK_TIMEOUT = 15
REAL_CHECK_CONCURRENCY = 30
XRAY_STARTUP_DELAY = 1
RETRY_COUNT = 0            # без повторов HTTP/HTTPS

TEST_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204"
]

MAX_LATENCY_MS = 500       # порог задержки (TCP)
ONLY_TCP = False

# Константы для проверки скорости (больше не используются, оставлены для совместимости)
SPEED_TEST_URL = "http://speedtest.tele2.net/512KB.zip"
MIN_SPEED_KBPS = 500

# ---------- GEOIP ----------
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
GEOIP_DB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"

def ensure_geoip_db():
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

reader = None
if ensure_geoip_db():
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception as e:
        logging.error(f"❌ Не удалось открыть базу GeoIP: {e}")
        reader = None

def get_country_flag(ip):
    if reader is None:
        return ""
    try:
        response = reader.country(ip)
        country_code = response.country.iso_code
        if country_code:
            return ''.join(chr(127397 + ord(c)) for c in country_code.upper())
    except Exception:
        pass
    return ""

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
@lru_cache(maxsize=256)
def resolve_host(host):
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
    return re.findall(r'(?:vless|ss|trojan|vmess|hysteria2|hy2)://[^\s<>"\']+', text)

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
        if src.startswith(('vless://', 'ss://', 'trojan://', 'vmess://', 'hysteria2://', 'hy2://')):
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

# ---------- ПАРСЕРЫ ----------
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
        explicit_sni = params.get('sni', [None])[0]
        return {
            'protocol': 'vless',
            'uuid': uuid,
            'host': host,
            'port': port,
            'security': security,
            'encryption': params.get('encryption', ['none'])[0],
            'type': params.get('type', ['tcp'])[0],
            'sni': explicit_sni if explicit_sni else host,
            'explicit_sni': explicit_sni,
            'fp': params.get('fp', ['chrome'])[0],
            'pbk': params.get('pbk', [''])[0],
            'sid': params.get('sid', [''])[0],
            'spx': params.get('spx', ['/'])[0],
            'flow': params.get('flow', [''])[0],
            'path': params.get('path', ['/'])[0],
            'host_header': params.get('host', [host])[0]
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга Vless: {e}")
        return None

def parse_ss_link(link):
    try:
        rest = link[5:]
        if '#' in rest:
            rest, _ = rest.split('#', 1)
        if '?' in rest:
            rest, _ = rest.split('?', 1)
        if '@' in rest:
            userinfo, hostport = rest.split('@', 1)
            if ':' in userinfo:
                method, password = userinfo.split(':', 1)
            else:
                return None
        else:
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
        if ':' in hostport:
            host, port_str = hostport.rsplit(':', 1)
            port = int(port_str)
        else:
            port = 443
        return {
            'protocol': 'ss',
            'host': host,
            'port': port,
            'method': method,
            'password': password,
            'original': link,
            'explicit_sni': None
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга SS: {e}")
        return None

def parse_trojan_link(link):
    try:
        parsed = urlparse(link)
        if parsed.scheme != 'trojan':
            return None
        password = parsed.username
        if not password:
            return None
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)
        peer_param = params.get('peer')
        sni_param = params.get('sni')
        explicit_sni = None
        if peer_param:
            explicit_sni = peer_param[0]
        elif sni_param:
            explicit_sni = sni_param[0]
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
        logging.debug(f"Ошибка парсинга Trojan: {e}")
        return None

def parse_vmess_link(link):
    try:
        # Формат: vmess://base64-encoded-json
        b64_part = link[8:]  # после vmess://
        if '#' in b64_part:
            b64_part = b64_part.split('#')[0]
        decoded = base64.b64decode(b64_part).decode('utf-8')
        cfg = json.loads(decoded)
        host = cfg.get('add')
        if not host:
            return None
        port = int(cfg.get('port', 443))
        uuid = cfg.get('id')
        if not uuid:
            return None
        security = cfg.get('scy', 'auto')
        network = cfg.get('net', 'tcp')
        path = cfg.get('path', '/')
        host_header = cfg.get('host', host)
        tls = cfg.get('tls') == 'tls'
        sni = cfg.get('peer') or host_header or host
        return {
            'protocol': 'vmess',
            'host': host,
            'port': port,
            'uuid': uuid,
            'security': security,
            'type': network,
            'path': path,
            'host_header': host_header,
            'tls': tls,
            'sni': sni,
            'explicit_sni': cfg.get('peer'),
            'allow_insecure': cfg.get('allowInsecure', False)
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга VMess: {e}")
        return None

def parse_hysteria2_link(link):
    try:
        if link.startswith('hysteria2://'):
            rest = link[12:]
        elif link.startswith('hy2://'):
            rest = link[6:]
        else:
            return None

        userinfo = None
        hostport = rest
        if '@' in rest:
            userinfo, hostport = rest.split('@', 1)

        password = None
        if userinfo:
            password = userinfo

        parsed = urlparse(f"//{hostport}")
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)

        insecure = params.get('insecure', ['0'])[0].lower() in ('1', 'true', 'yes')
        sni = params.get('sni', [host])[0]
        up = params.get('up', [''])[0]
        down = params.get('down', [''])[0]
        obfs = params.get('obfs', [''])[0]

        return {
            'protocol': 'hysteria2',
            'host': host,
            'port': port,
            'password': password,
            'sni': sni,
            'explicit_sni': sni if sni != host else None,
            'allow_insecure': insecure,
            'up': up,
            'down': down,
            'obfs': obfs
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга Hysteria2: {e}")
        return None

def parse_link(link):
    if link.startswith('vless://'):
        return parse_vless_link(link)
    elif link.startswith('ss://'):
        return parse_ss_link(link)
    elif link.startswith('trojan://'):
        return parse_trojan_link(link)
    elif link.startswith('vmess://'):
        return parse_vmess_link(link)
    elif link.startswith(('hysteria2://', 'hy2://')):
        return parse_hysteria2_link(link)
    else:
        return None

def shorten_link(link):
    """Возвращает протокол://хост:порт (или обрезает до первого ?)"""
    parsed = parse_link(link)
    if parsed:
        return f"{parsed['protocol']}://{parsed['host']}:{parsed['port']}"
    q_pos = link.find('?')
    if q_pos != -1:
        return link[:q_pos]
    return link[:80]

# ---------- СОЗДАНИЕ КОНФИГА XRAY ----------
def create_xray_config(config):
    base_config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": SOCKS_PORT,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}
        }],
        "outbounds": []
    }
    protocol = config['protocol']

    if protocol == 'vless':
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": config['host'],
                    "port": config['port'],
                    "users": [{
                        "id": config['uuid'],
                        "encryption": config.get('encryption', 'none'),
                        "flow": config.get('flow', '')
                    }]
                }]
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
                "fingerprint": config.get('fp', 'random'),
                "publicKey": config.get('pbk', ''),
                "shortId": config.get('sid', ''),
                "spiderX": config.get('spx', '/')
            }
        if config.get('type') == 'ws':
            outbound["streamSettings"]["wsSettings"] = {
                "path": config.get('path', '/'),
                "headers": {"Host": config.get('host_header', config['host'])}
            }

    elif protocol == 'vmess':
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": config['host'],
                    "port": config['port'],
                    "users": [{
                        "id": config['uuid'],
                        "security": config.get('security', 'auto')
                    }]
                }]
            },
            "streamSettings": {
                "network": config.get('type', 'tcp'),
                "security": config.get('tls', False) and "tls" or "none"
            }
        }
        if config.get('tls'):
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": config.get('sni', config['host']),
                "allowInsecure": config.get('allow_insecure', False)
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
                "servers": [{
                    "address": config['host'],
                    "port": config['port'],
                    "method": config['method'],
                    "password": config['password']
                }]
            },
            "streamSettings": {"network": "tcp", "security": "none"}
        }

    elif protocol == 'trojan':
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": config['host'],
                    "port": config['port'],
                    "password": config['password']
                }]
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

    elif protocol == 'hysteria2':
        outbound = {
            "protocol": "hysteria2",
            "settings": {
                "server": config['host'],
                "port": config['port'],
                "password": config['password'],
                "tls": {
                    "sni": config.get('sni', config['host']),
                    "insecure": config.get('allow_insecure', False)
                }
            }
        }
        if config.get('up') or config.get('down'):
            outbound["settings"]["bandwidth"] = {}
            if config.get('up'):
                outbound["settings"]["bandwidth"]["up"] = config['up']
            if config.get('down'):
                outbound["settings"]["bandwidth"]["down"] = config['down']
        if config.get('obfs'):
            outbound["settings"]["obfs"] = config['obfs']

    else:
        return None

    base_config["outbounds"].append(outbound)
    return base_config

# ---------- TCP ПРОВЕРКА (одна попытка + задержка) ----------
def check_tcp(link):
    parsed = parse_link(link)
    if not parsed:
        return (link, False, None, None)
    host, port = parsed['host'], parsed['port']
    try:
        ip = resolve_host(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_CHECK_TIMEOUT)
        start = time.time()
        result = sock.connect_ex((ip, port))
        latency = int((time.time() - start) * 1000)
        sock.close()
        if result == 0 and latency <= MAX_LATENCY_MS:
            return (link, True, ip, latency)
        else:
            return (link, False, ip, latency)
    except Exception:
        return (link, False, None, None)

# ---------- РЕАЛЬНАЯ ПРОВЕРКА (одна попытка HTTP, одна HTTPS при необходимости) ----------
def check_real(link):
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
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(XRAY_STARTUP_DELAY)
        proxies = {
            'http': f'socks5h://127.0.0.1:{SOCKS_PORT}',
            'https': f'socks5h://127.0.0.1:{SOCKS_PORT}'
        }

        # Определяем, нужно ли проверять HTTPS (для TLS-ключей)
        needs_https = False
        if config_dict['protocol'] in ('vless', 'vmess', 'trojan', 'hysteria2'):
            if config_dict['protocol'] == 'vmess':
                needs_https = config_dict.get('tls', False)
            elif config_dict['protocol'] == 'hysteria2':
                needs_https = True
            else:
                security = config_dict.get('security', 'none')
                if security in ('tls', 'reality'):
                    needs_https = True

        # HTTP-проверка (одна попытка)
        http_success = False
        for test_url in TEST_URLS:
            try:
                resp = requests.get(
                    test_url, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                    headers={'User-Agent': USER_AGENT}, allow_redirects=False
                )
                http_success = True
                break
            except Exception:
                continue

        if not http_success:
            return (link, False, None)

        # Дополнительная проверка HTTPS (одна попытка, если нужна)
        if needs_https:
            try:
                https_test = "https://www.google.com/generate_204"
                resp = requests.get(https_test, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                                    headers={'User-Agent': USER_AGENT}, verify=False)
                # если успех, ничего не делаем
            except Exception:
                return (link, False, None)

        # Все проверки пройдены
        return (link, True, None)

    except Exception as e:
        logging.debug(f"Ошибка при проверке {link[:60]}: {e}")
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

# ---------- ДВУХУРОВНЕВАЯ ФИЛЬТРАЦИЯ С ОТСЕВОМ ПО ФЛАГУ ----------
def filter_working_links(links):
    global record_counter, current_check, total_checks
    total_checks = len(links)
    logging.info(f"🚀 Начинаю фильтрацию {total_checks} ссылок")

    # ---------- Этап 1: TCP (одна попытка + задержка) ----------
    logging.info(f"🌐 Этап 1: TCP-проверка (задержка ≤ {MAX_LATENCY_MS} мс)...")
    tcp_success = []  # (link, ip, latency)
    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        future_to_link = {executor.submit(check_tcp, link): link for link in links}
        for future in as_completed(future_to_link):
            current_check += 1
            link, ok, ip, latency = future.result()
            if ok:
                tcp_success.append((link, ip, latency))
    logging.info(f"📊 TCP-проверка завершена. Прошли (TCP+latency): {len(tcp_success)}/{total_checks}")

    if not tcp_success:
        return []

    # ---------- Этап 2: GeoIP ----------
    logging.info(f"🌍 Определение флагов для {len(tcp_success)} серверов...")
    links_with_flags = []  # (link, flag)
    for link, ip, latency in tcp_success:
        flag = get_country_flag(ip) if ip else ""
        if flag:
            links_with_flags.append((link, flag))
        else:
            short = shorten_link(link)
            logging.debug(f"Сервер без флага отсеян: {short} (latency={latency} мс)")

    logging.info(f"🧾 Серверов с флагами: {len(links_with_flags)}")

    if not links_with_flags:
        return []

    if ONLY_TCP:
        logging.info("⏩ Режим ONLY_TCP – реальная проверка пропущена")
        return links_with_flags

    # ---------- Этап 3: реальная проверка (однократная) ----------
    logging.info(f"🧪 Этап 3: Реальная проверка {len(links_with_flags)} ссылок...")
    working_links_with_flags = []  # (link, flag)
    stage_total = len(links_with_flags)
    stage_current = 0
    links_to_check = [link for link, _ in links_with_flags]

    with ThreadPoolExecutor(max_workers=REAL_CHECK_CONCURRENCY) as executor:
        future_to_link = {executor.submit(check_real, link): link for link in links_to_check}
        for future in as_completed(future_to_link):
            stage_current += 1
            current_check += 1
            record_counter += 1
            link, is_working, _ = future.result()
            short = shorten_link(link)

            # Определяем протокол для лога
            if link.startswith('vless://'):
                proto = 'vless'
            elif link.startswith('ss://'):
                proto = 'ss'
            elif link.startswith('trojan://'):
                proto = 'trojan'
            elif link.startswith('vmess://'):
                proto = 'vmess'
            elif link.startswith(('hysteria2://', 'hy2://')):
                proto = 'hy2'
            else:
                proto = '?'

            # Находим соответствующий флаг
            flag_dict = dict(links_with_flags)
            flag = flag_dict[link]

            if is_working:
                working_links_with_flags.append((link, flag))
                emoji = "✅"
            else:
                emoji = "❌"

            log_msg = f"{proto} {emoji} [{stage_current}/{stage_total}]: {short}"
            logging.info(log_msg)

    logging.info(f"📊 Реальная проверка завершена. Рабочих с флагами: {len(working_links_with_flags)}/{stage_total}")
    return working_links_with_flags

# ---------- СОХРАНЕНИЕ РЕЗУЛЬТАТОВ (ИСПОЛЬЗУЕМ ГОТОВЫЕ ФЛАГИ) ----------
def save_working_links(links_with_flags):
    logging.info(f"💾 Сохраняю {len(links_with_flags)} рабочих ссылок в {OUTPUT_FILE}")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"#profile-title:{PROFILE_TITLE}\n")
        f.write(f"#subscription-userinfo:{SUBSCRIPTION_USERINFO}\n")
        f.write(f"#profile-update-interval:{PROFILE_UPDATE_INTERVAL}\n")
        f.write(f"#support-url:{SUPPORT_URL}\n")
        f.write(f"#profile-web-page-url:{PROFILE_WEB_PAGE_URL}\n")
        f.write(f"#announce: АКТИВНЫХ ТОННЕЛЕЙ 🚀 {len(links_with_flags)} | ОБНОВЛЕНО 📅 {TODAY_STR}\n")
        for idx, (link, flag) in enumerate(links_with_flags, start=1):
            link_clean = re.sub(r'#.*$', '', link)
            server_num = f"{idx:04d}"
            config = parse_link(link_clean)
            sni_part = None
            if config:
                explicit_sni = config.get('explicit_sni')
                if explicit_sni:
                    sni_part = f"SNI- {explicit_sni}"
            tag_parts = [f"#🔑📡 {server_num}"]
            if flag:
                tag_parts.append(flag)
            if sni_part:
                tag_parts.append(sni_part)
            tag = " | ".join(tag_parts)
            f.write(link_clean + tag + '\n')
    logging.info(f"💾 Сохранено {len(links_with_flags)} рабочих ссылок в {OUTPUT_FILE}")

def create_base64_subscription():
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
    global record_counter, current_check, total_checks
    logging.info("🟢 Запуск генератора подписок (протоколы: Vless, SS, Trojan, VMess, Hysteria2; одна попытка на этап, отсев по latency > {} мс на TCP)".format(MAX_LATENCY_MS))
    if not check_xray_available():
        logging.error("Xray-core обязателен. Завершение.")
        return

    sources = read_sources()
    if not sources:
        return

    all_links = gather_all_links(sources)
    if not all_links:
        return

    record_counter = 0
    current_check = 0
    total_checks = len(all_links)

    working_links_with_flags = filter_working_links(all_links)
    written = len(working_links_with_flags)
    if written > 0:
        save_working_links(working_links_with_flags)
        create_base64_subscription()
    else:
        logging.warning("Нет рабочих ссылок с флагами – файлы не созданы.")

    logging.info(f"📊 Итог: {written} рабочих с флагами из {len(all_links)} проверенных")
    logging.info("🏁 Работа завершена")

if __name__ == "__main__":
    main()
