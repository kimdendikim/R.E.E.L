#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BlackSearch — full single-file Telegram bot.

Features:
 - /start, /help, /ping, /version
 - /phone <num>  — phone analysis (NumVerify, AbstractAPI if keys)
 - /email <addr> — email analysis (AbstractAPI if key)
 - /ip <ip>      — IP analysis (ipinfo)
 - /dork <query> — generate dorks and search via duckduckgo-search (returns real links)
 - /user <username> — profile URL generation + dork-search variations
 - /breach <email> — HaveIBeenPwned breach check
 - /vt-url <url>  — VirusTotal URL scan & simple summary
 - /enrich <value> — Explorium enrichment (example)
 - /report <type> <value> — save local JSON report and send file
 - /archive <filename> — list/send local report (S3 optional placeholder)
 - robust logging, getMe check, error handling
"""

import os
import sys
import time
import json
import uuid
import logging
import requests
from pathlib import Path
from datetime import datetime
from typing import List, Set, Dict

# Optional niceties: rich console and art for banners (not required)
try:
    from rich.console import Console
    from rich.panel import Panel
    from art import text2art
    console = Console()
except Exception:
    console = None

# dotenv support
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# duckduckgo-search for reliable DDG results
try:
    from duckduckgo_search import DDGS
except Exception:
    DDGS = None

# BeautifulSoup fallback
from bs4 import BeautifulSoup

# Telegram (python-telegram-bot v13)
from telegram import ParseMode, InputFile
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters

# ----------------------------
# CONFIG: tokens & API keys
# All keys inserted from user-provided values
# ----------------------------
TELEGRAM_TOKEN = "8412221974:AAHJiv6EuKnRFx2GoAISNuxpa6bygjqoKwM"

# Phone / Email / IP / VK / DaData / LeakOsint etc.
ABSTRACT_API_KEY_PHONE = "ed76df700b40404b853cdf9f30e0aef6"
ABSTRACT_API_KEY_EMAIL = "6e7b9deb434b4b4a88ff808260725343"
NUMVERIFY_API_KEY = "2d3c0b9d3739a135bd499f5e83094603"
IPGEO_API_KEY = "178e08dfc89f46a28ee1cff258e41bcb"

DADATA_API_TOKEN = "b293b21b89479e85df4d0ab1007d34e4e4961712"
DADATA_API_SECRET = "29879ff4cc4c0679d8cf2f98a21be4f983c2b53d"
DADATA_URL = "https://suggestions.dadata.ru/suggestions/api/4_1/rs/suggest/party"

LEAKOSINT_TOKEN = "7949201327:7z2O7xWq"
LEAKOSINT_URL = "https://leakosintapi.com/"

VK_TOKEN = "0af157510af157510af15751aa0a89e69600af10af157516a0bc15996e74fe2b440998c"
VK_API_VERSION = "5.131"

# New keys supplied by you
HIBP_API_KEY = "b4368667cd5c34f4234e3a226d6f3164444a72f4bc769c86c4a29d424ba2dd2"
ARCHIVE_S3_KEY = "S1c56qjUngB5zuxo"
VIRUSTOTAL_KEY = "84bf67372e97d51ddb739d9b4830c0e5"
NUMVERIFY_KEY = "c61336f10cf7b088ea317e21f75a22f3"
EXPLORIUM_KEY1 = "2f9049de-ad8f-410a-a9f3-8da2b4d49242"
EXPLORIUM_KEY2 = ("VVwPrr4Tl0hpW1nhl2M2WxS60W2F3lfm5CKFtXN2K0T343lYM-"
                   "W6N1vHY6lZ3nqW6Y9NrH1YGnlQW6QNgHP7s9LKdW4S60H81wRYVHVfv"
                   "Gqp95KcdwW36T_xz3JhP0DW2FJ8zH6J1tCwW8NwDzc5wgYsHW8DXyFc"
                   "1kbvv8W3lz5dn72HxCMW5")

# OPTIONAL: AWS creds from env (if you want S3 uploads later)
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
S3_BUCKET = os.getenv("S3_BUCKET", "")

# ----------------------------
# Settings & storage
# ----------------------------
DATA_FOLDER = Path("data")
DATA_FOLDER.mkdir(parents=True, exist_ok=True)

# Dork/search limits
MAX_DORK_QUERIES = 6
MAX_LINKS_RETURN = 12
DDG_SEARCH_DELAY = 0.9  # seconds between DDG queries to be polite

# Banner (compact)
BANNER = r"""
    ____       ______   ______     __     
   |  _ \     |  ____| |  ____|   / /     
   | |_) |    | |__    | |__     / /      
   |  _ <     |  __|   |  __|   / /       
   | |_\ \    | |____  | |____ / /___     
   |____\_\   |______| |______|_____/     
"""

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("BlackSearchFull")

# ----------------------------
# Utility functions
# ----------------------------
def pretty_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)

def send_banner_text(update, text: str):
    """Send banner + text. Uses code block for banner to preserve formatting."""
    try:
        update.message.reply_text(f"```{BANNER}```\n{text}", parse_mode=ParseMode.MARKDOWN)
    except Exception:
        try:
            update.message.reply_text(BANNER + "\n" + text)
        except Exception:
            logger.exception("Failed to send banner text")

def safe_short(text: str, limit: int = 4000) -> str:
    return text if len(text) <= limit else text[:limit-3] + "..."

# ----------------------------
# DuckDuckGo search helpers (using duckduckgo-search lib with HTML fallback)
# ----------------------------
def ddg_lib_search(query: str, max_results: int = 10) -> List[Dict]:
    if DDGS is None:
        return []
    out = []
    try:
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=max_results):
                out.append({"title": r.get("title", ""), "href": r.get("href", ""), "body": r.get("body", "")})
    except Exception:
        logger.exception("ddg_lib_search failed")
    return out

def ddg_html_search(query: str, max_results: int = 10) -> List[Dict]:
    url = "https://html.duckduckgo.com/html/"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BlackSearch/1.0)"}
    try:
        resp = requests.post(url, data={"q": query}, headers=headers, timeout=15)
        if resp.status_code != 200:
            logger.warning("DDG HTML returned %s", resp.status_code)
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        results = []
        for a in soup.select("a.result__a")[:max_results]:
            href = a.get("href")
            title = a.get_text(strip=True)
            if href and href.startswith("http"):
                results.append({"title": title, "href": href, "body": ""})
        if not results:
            for a in soup.find_all("a", href=True)[:max_results]:
                href = a["href"]
                if href.startswith("http"):
                    results.append({"title": a.get_text(strip=True), "href": href, "body": ""})
        return results
    except Exception:
        logger.exception("ddg_html_search failed")
        return []

def search_ddg_links(query: str, limit: int = 10) -> List[str]:
    # try library then HTML fallback
    links = []
    seen = set()
    lib = ddg_lib_search(query, max_results=limit)
    for r in lib:
        href = r.get("href", "")
        if href and href not in seen:
            seen.add(href); links.append(href)
        if len(links) >= limit: return links
    html = ddg_html_search(query, max_results=limit)
    for r in html:
        href = r.get("href", "")
        if href and href not in seen:
            seen.add(href); links.append(href)
        if len(links) >= limit: return links
    return links

def generate_dorks(query: str) -> List[str]:
    q = query.strip()
    patterns = [
        q,
        f'site:edu {q}',
        f'site:gov {q}',
        f'inurl:{q}',
        f'intitle:{q}',
        f'"{q}" filetype:pdf',
        f'{q} "contact"',
        f'{q} "curriculum vitae" OR "CV"'
    ]
    out = []
    for p in patterns:
        if p not in out:
            out.append(p)
        if len(out) >= MAX_DORK_QUERIES:
            break
    return out

# ----------------------------
# Social profile templates
# ----------------------------
SOCIAL_PLATFORMS = {
    'GitHub': 'https://github.com/{}',
    'Twitter': 'https://twitter.com/{}',
    'Instagram': 'https://instagram.com/{}',
    'Reddit': 'https://reddit.com/user/{}',
    'VK': 'https://vk.com/{}',
    'Telegram': 'https://t.me/{}',
    'YouTube': 'https://youtube.com/{}',
    'Pinterest': 'https://pinterest.com/{}',
    'Tumblr': 'https://{}.tumblr.com',
    'DeviantArt': 'https://{}.deviantart.com',
    'Flickr': 'https://flickr.com/people/{}',
    'Medium': 'https://medium.com/@{}',
    'LinkedIn': 'https://www.linkedin.com/in/{}'
}

def generate_profile_links(username: str) -> Dict[str,str]:
    out = {}
    for k,t in SOCIAL_PLATFORMS.items():
        out[k] = t.format(username)
    return out

# ----------------------------
# Command handlers
# ----------------------------
def cmd_start(update, context):
    txt = ("Привет! BlackSearch — OSINT & security bot.\n\n"
           "Команды: /help, /phone, /email, /ip, /dork, /user, /breach, /vt-url, /enrich, /report, /archive\n\n"
           "Используй ответственно.")
    send_banner_text(update, txt)

def cmd_help(update, context):
    cmd_start(update, context)

def cmd_ping(update, context):
    send_banner_text(update, f"🏓 Pong — {datetime.utcnow().isoformat()}Z")

def cmd_version(update, context):
    send_banner_text(update, "BlackSearch v1.0 — single-file OSINT bot")

# Phone analysis
def cmd_phone(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /phone +79998887766")
        return
    phone = context.args[0].strip()
    header = f"🔎 Анализ номера: `{phone}`\n"
    results = {}
    if ABSTRACT_API_KEY_PHONE:
        try:
            url = f"https://phonevalidation.abstractapi.com/v1/?api_key={ABSTRACT_API_KEY_PHONE}&phone={phone}"
            r = requests.get(url, timeout=10).json()
            results["abstractapi"] = r
        except Exception as e:
            results["abstractapi_error"] = str(e)
    if NUMVERIFY_API_KEY:
        try:
            url = "http://apilayer.net/api/validate"
            r = requests.get(url, params={"access_key": NUMVERIFY_API_KEY, "number": phone}, timeout=10).json()
            results["numverify"] = r
        except Exception as e:
            results["numverify_error"] = str(e)
    if not results:
        demo = {"number": phone, "valid": "unknown (demo)", "note": "Нет ключей NumVerify/AbstractAPI"}
        send_banner_text(update, header + "```json\n" + pretty_json(demo) + "\n```")
    else:
        send_banner_text(update, header + "```json\n" + pretty_json(results) + "\n```")

# Email analysis
def cmd_email(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /email test@example.com")
        return
    email = context.args[0].strip()
    header = f"🔎 Анализ email: `{email}`\n"
    if ABSTRACT_API_KEY_EMAIL:
        try:
            url = f"https://emailvalidation.abstractapi.com/v1/?api_key={ABSTRACT_API_KEY_EMAIL}&email={email}"
            r = requests.get(url, timeout=10).json()
            send_banner_text(update, header + "```json\n" + pretty_json(r) + "\n```")
        except Exception as e:
            send_banner_text(update, header + f"❌ Error: {e}")
    else:
        demo = {"email": email, "deliverable": "unknown (demo)", "note": "Нет ABSTRACT_API_KEY_EMAIL"}
        send_banner_text(update, header + "```json\n" + pretty_json(demo) + "\n```")

# IP Analysis
def cmd_ip(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /ip 8.8.8.8")
        return
    ip = context.args[0].strip()
    header = f"🔎 Анализ IP: `{ip}`\n"
    try:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {}
        if os.getenv("IPINFO_TOKEN", ""):
            headers["Authorization"] = f"Bearer {os.getenv('IPINFO_TOKEN')}"
        r = requests.get(url, headers=headers, timeout=10).json()
        send_banner_text(update, header + "```json\n" + pretty_json(r) + "\n```")
    except Exception as e:
        send_banner_text(update, header + f"❌ Error: {e}")

# Dorking
def cmd_dork(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /dork <запрос>")
        return
    query = " ".join(context.args).strip()
    send_banner_text(update, f"🔎 Dorking: `{query}` — генерирую паттерны и ищу (макс {MAX_DORK_QUERIES} паттернов)...")
    dorks = generate_dorks(query)
    found_links: List[str] = []
    seen: Set[str] = set()
    for dork in dorks:
        time.sleep(DDG_SEARCH_DELAY)
        links = search_ddg_links(dork, limit=MAX_LINKS_RETURN)
        for l in links:
            if l not in seen:
                seen.add(l); found_links.append(l)
            if len(found_links) >= MAX_LINKS_RETURN: break
        if len(found_links) >= MAX_LINKS_RETURN: break
    if not found_links:
        send_banner_text(update, "ℹ️ Ничего не найдено по сгенерированным доркам.")
        return
    lines = ["🔗 Результаты (сайты):"]
    for i, link in enumerate(found_links[:MAX_LINKS_RETURN], start=1):
        lines.append(f"{i}. {link}")
    send_banner_text(update, "\n".join(lines))

# User search
def cmd_user(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /user <username>")
        return
    username = context.args[0].strip()
    send_banner_text(update, f"🔎 Поиск профилей для: `{username}` — формирую прямые ссылки и запускаю поиск...")
    profiles = generate_profile_links(username)
    profile_lines = ["🔗 Прямые профили (шаблоны):"]
    for name, url in profiles.items():
        profile_lines.append(f"- {name}: {url}")
    try:
        update.message.reply_text("\n".join(profile_lines))
    except Exception:
        pass
    # search variants
    variants = [
        username,
        f'"{username}" profile',
        f'{username} "profile"',
        f'site:github.com {username}',
        f'site:vk.com {username}',
        f'{username} "instagram.com"',
    ]
    found_links: List[str] = []
    seen: Set[str] = set()
    for v in variants:
        time.sleep(DDG_SEARCH_DELAY)
        links = search_ddg_links(v, limit=MAX_LINKS_RETURN)
        for l in links:
            if l not in seen:
                seen.add(l); found_links.append(l)
            if len(found_links) >= MAX_LINKS_RETURN: break
        if len(found_links) >= MAX_LINKS_RETURN: break
    if found_links:
        lines = ["🔎 Найдено по поиску (внешние ссылки):"]
        for i, link in enumerate(found_links[:MAX_LINKS_RETURN], start=1):
            lines.append(f"{i}. {link}")
        try:
            update.message.reply_text("\n".join(lines))
        except Exception:
            send_banner_text(update, "\n".join(lines))
    else:
        send_banner_text(update, "ℹ️ Поиск по юзернейму не вернул дополнительных ссылок.")

# HIBP breach check
def cmd_breach(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /breach user@example.com")
        return
    email = context.args[0].strip()
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": HIBP_API_KEY, "User-Agent": "BlackSearch-bot/1.0"}
    try:
        r = requests.get(url, headers=headers, params={"truncateResponse":"false"}, timeout=15)
        if r.status_code == 200:
            data = r.json()
            lines = [f"Найдено {len(data)} утечек для {email}:"]
            for b in data:
                lines.append(f"- {b.get('Name')} ({b.get('BreachDate')}) — {b.get('Title')}")
            send_banner_text(update, "\n".join(lines))
        elif r.status_code == 404:
            send_banner_text(update, f"Не найдено утечек для {email}.")
        elif r.status_code == 401:
            send_banner_text(update, "HIBP: Unauthorized — проверь ключ.")
        else:
            send_banner_text(update, f"HIBP returned {r.status_code}: {safe_short(r.text)}")
    except Exception as e:
        send_banner_text(update, f"Ошибка HIBP: {e}")

# VirusTotal URL scan (basic)
def cmd_vt_url(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /vt-url https://example.com")
        return
    target = context.args[0].strip()
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    try:
        submit_url = "https://www.virustotal.com/api/v3/urls"
        resp = requests.post(submit_url, headers=headers, data={"url": target}, timeout=20)
        if resp.status_code not in (200, 201):
            send_banner_text(update, f"VT submit error {resp.status_code}: {safe_short(resp.text)}")
            return
        analysis_id = resp.json()["data"]["id"]
        time.sleep(2)
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        r2 = requests.get(report_url, headers=headers, timeout=20)
        if r2.status_code == 200:
            j = r2.json()
            stats = j.get("data", {}).get("attributes", {}).get("stats", {})
            send_banner_text(update, "VirusTotal analysis stats:\n" + pretty_json(stats))
        else:
            send_banner_text(update, f"VT report error {r2.status_code}: {safe_short(r2.text)}")
    except Exception as e:
        send_banner_text(update, f"Ошибка VirusTotal: {e}")

# Explorium enrichment (example stub)
def cmd_enrich(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /enrich <value>")
        return
    value = " ".join(context.args).strip()
    # Example Explorium endpoint — adjust per your account docs
    url = "https://api.explorium.ai/enrich"
    headers = {"Authorization": f"Bearer {EXPLORIUM_KEY1}", "Content-Type": "application/json"}
    payload = {"query": value}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code == 200:
            send_banner_text(update, "Explorium enrichment result:\n" + pretty_json(r.json()))
        else:
            send_banner_text(update, f"Explorium error {r.status_code}: {safe_short(r.text)}")
    except Exception as e:
        send_banner_text(update, f"Ошибка Explorium: {e}")

# Report saving & sending
def cmd_report(update, context):
    if len(context.args) < 2:
        send_banner_text(update, "⚠️ Использование: /report <type> <value>")
        return
    rtype = context.args[0]
    value = " ".join(context.args[1:])
    payload = {
        "id": str(uuid.uuid4()),
        "type": rtype,
        "value": value,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "meta": {"generated_by": "BlackSearchFull"}
    }
    fname = DATA_FOLDER / f"report_{payload['id']}.json"
    with open(fname, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    send_banner_text(update, f"✅ Отчёт сохранён: `{fname.name}` — отправляю файл...")
    try:
        with open(fname, "rb") as fh:
            update.message.reply_document(document=fh, filename=fname.name)
    except Exception:
        logger.exception("Failed to send report file")
        send_banner_text(update, "Не удалось отправить файл — проверь логи.")

# Archive/send file (local). S3 upload would be here if configured.
def cmd_archive(update, context):
    if not context.args:
        send_banner_text(update, "⚠️ Использование: /archive <filename>")
        return
    fname = context.args[0].strip()
    path = DATA_FOLDER / fname
    if not path.exists():
        send_banner_text(update, f"Файл не найден: {path}")
        return
    # send file
    try:
        with open(path, "rb") as fh:
            update.message.reply_document(document=fh, filename=path.name)
    except Exception:
        logger.exception("Failed to send archive file")
        send_banner_text(update, "Не удалось отправить файл — проверь логи.")

def unknown_handler(update, context):
    send_banner_text(update, "Неизвестная команда. Введите /help")

# ----------------------------
# Main
# ----------------------------
def main():
    # token quick check
    if not TELEGRAM_TOKEN or TELEGRAM_TOKEN.startswith("YOUR"):
        print("ERROR: TELEGRAM_TOKEN is not set. Edit the script to insert your token.")
        return
    try:
        r = requests.get(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getMe", timeout=10)
        j = r.json()
        print("getMe status:", r.status_code, "ok:", j.get("ok"))
        if not j.get("ok"):
            print("Telegram getMe error:", j)
            return
        print("Bot info:", j.get("result"))
    except Exception as e:
        print("Failed getMe:", e)
        return

    try:
        updater = Updater(TELEGRAM_TOKEN, use_context=True)
    except Exception as e:
        print("Failed create Updater:", e)
        return

    dp = updater.dispatcher

    # register handlers
    dp.add_handler(CommandHandler("start", cmd_start))
    dp.add_handler(CommandHandler("help", cmd_help))
    dp.add_handler(CommandHandler("ping", cmd_ping))
    dp.add_handler(CommandHandler("version", cmd_version))
    dp.add_handler(CommandHandler("phone", cmd_phone))
    dp.add_handler(CommandHandler("email", cmd_email))
    dp.add_handler(CommandHandler("ip", cmd_ip))
    dp.add_handler(CommandHandler("dork", cmd_dork))
    dp.add_handler(CommandHandler("user", cmd_user))
    dp.add_handler(CommandHandler("breach", cmd_breach))
    dp.add_handler(CommandHandler("vt_url", cmd_vt_url))
    dp.add_handler(CommandHandler("enrich", cmd_enrich))
    dp.add_handler(CommandHandler("report", cmd_report))
    dp.add_handler(CommandHandler("archive", cmd_archive))
    dp.add_handler(MessageHandler(Filters.command, unknown_handler))

    # error handler
    def handle_error(update, context):
        logger.exception("Handler error", exc_info=context.error)
        try:
            update.message.reply_text(BANNER + "\nПроизошла внутренняя ошибка, проверьте логи.")
        except Exception:
            pass

    dp.add_error_handler(handle_error)

    print("Registered handlers:", {k: len(v) for k,v in dp.handlers.items()})
    logger.info("Starting bot polling...")
    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
