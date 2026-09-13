#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# PhoneInfoga - Phone Numbers OSINT Tool
# Merged single-file Flask API for Vercel deployment
#

import sys
import re
import json
import hashlib
import random
import requests
from urllib.parse import urlencode
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app)  # Allow all origins (frontend call kar sake)

# Rate limiting: 5 requests/minute, 100/day per IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "5 per minute"],
    storage_uri="memory://",
)

# ─────────────────────────────────────────────
# OSINT DATA (inline — no file dependencies)
# ─────────────────────────────────────────────

INDIVIDUALS = [
    {"site": "Google", "dialCode": None, "request": "site:truecaller.com \"$i\"", "stop": 5},
    {"site": "Sync.me", "dialCode": None, "request": "site:sync.me \"$i\"", "stop": 5},
    {"site": "Infobel", "dialCode": None, "request": "site:infobel.com \"$i\"", "stop": 5},
]

REPUTATION = [
    {"title": "Spam reports", "request": "\"$i\" spam OR scam OR fraud", "stop": 5},
    {"title": "Complaints", "request": "\"$i\" complaint OR report", "stop": 5},
]

SOCIAL_MEDIAS = [
    {"site": "Facebook", "request": "site:facebook.com \"$i\"", "stop": 5},
    {"site": "LinkedIn", "request": "site:linkedin.com \"$i\"", "stop": 5},
    {"site": "Twitter", "request": "site:twitter.com \"$i\"", "stop": 5},
]

DISPOSABLE_PROVIDERS = [
    {"site": "ReceiveSMS", "request": "site:receive-sms.cc \"$n\"", "stop": 3},
    {"site": "FreeReceiveSMS", "request": "site:freereceivesmsonline.com \"$n\"", "stop": 3},
]

# ─────────────────────────────────────────────
# USER AGENTS
# ─────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14",
    "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3",
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 Chrome/16.0.912.63 Safari/535.7",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0",
]

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def format_number(input_number):
    return re.sub(r"(?:\+)?(?:[^0-9]*)", "", input_number)


def replace_variables(string, number):
    string = string.replace("$n", number.get("default", ""))
    string = string.replace("$i", number.get("international", ""))
    local_part = number.get("international", "").replace(
        "{} ".format(number.get("countryCode", "")), ""
    )
    string = string.replace("$l", local_part)
    return string


def http_get(url, headers=None):
    h = headers or {}
    h["User-Agent"] = random.choice(USER_AGENTS)
    requests.packages.urllib3.disable_warnings()
    return requests.get(url, headers=h, timeout=10, verify=False)


# ─────────────────────────────────────────────
# LOCAL SCAN
# ─────────────────────────────────────────────

def local_scan(input_number):
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as pntimezone
    except ImportError:
        return {"error": "phonenumbers library not installed"}

    formatted = "+" + format_number(input_number)

    try:
        phone_obj = phonenumbers.parse(formatted, None)
    except Exception:
        return None

    if not phonenumbers.is_valid_number(phone_obj):
        return None

    number = phonenumbers.format_number(
        phone_obj, phonenumbers.PhoneNumberFormat.E164
    ).replace("+", "")

    country_code = phonenumbers.format_number(
        phone_obj, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    ).split(" ")[0]

    country_iso = phonenumbers.region_code_for_country_code(int(country_code))
    local_number = phonenumbers.format_number(
        phone_obj, phonenumbers.PhoneNumberFormat.E164
    ).replace(country_code, "")
    international_number = phonenumbers.format_number(
        phone_obj, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )

    country = geocoder.country_name_for_number(phone_obj, "en")
    location = geocoder.description_for_number(phone_obj, "en")
    carrier_name = carrier.name_for_number(phone_obj, "en")
    timezones = list(pntimezone.time_zones_for_number(phone_obj))
    is_possible = phonenumbers.is_possible_number(phone_obj)

    return {
        "input": input_number,
        "default": number,
        "local": local_number,
        "international": international_number,
        "country": country,
        "countryCode": country_code,
        "countryIsoCode": country_iso,
        "location": location,
        "carrier": carrier_name,
        "timezones": timezones,
        "valid": True,
        "possible": is_possible,
    }


# ─────────────────────────────────────────────
# NUMVERIFY SCAN
# ─────────────────────────────────────────────

def numverify_scan(number):
    try:
        from bs4 import BeautifulSoup
        res = http_get("https://numverify.com/")
        soup = BeautifulSoup(res.text, "html5lib")
    except Exception:
        return {"error": "Numverify.com is not available"}

    request_secret = ""
    for tag in soup.find_all("input", type="hidden"):
        if tag.get("name") == "scl_request_secret":
            request_secret = tag.get("value", "")
            break

    api_key = hashlib.md5((number + request_secret).encode("utf-8")).hexdigest()

    headers = {
        "Host": "numverify.com",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Referer": "https://numverify.com/",
        "X-Requested-With": "XMLHttpRequest",
    }

    try:
        res = http_get(
            "https://numverify.com/php_helper_scripts/phone_api.php"
            "?secret_key={}&number={}".format(api_key, number),
            headers=headers,
        )
        data = json.loads(res.content.decode("utf-8"))
    except Exception:
        return {"error": "Numverify.com is not available"}

    if isinstance(data, dict) and "error" in data:
        return {"error": "Numverify: " + str(data["error"])}

    return {
        "number": "({}){} ".format(data.get("country_prefix", ""), data.get("local_format", "")),
        "country": "{} ({})".format(data.get("country_name", ""), data.get("country_code", "")),
        "location": data.get("location", ""),
        "carrier": data.get("carrier", ""),
        "line_type": data.get("line_type", ""),
        "valid": data.get("valid", False),
    }


# ─────────────────────────────────────────────
# OVH SCAN
# ─────────────────────────────────────────────

def ovh_scan(local_number, country_iso):
    try:
        res = requests.get(
            "https://api.ovh.com/1.0/telephony/number/detailedZones",
            params={"country": country_iso.lower()},
            headers={"accept": "application/json", "User-Agent": random.choice(USER_AGENTS)},
            timeout=10,
        )
        data = json.loads(res.content.decode("utf-8"))
    except Exception:
        return {"error": "OVH API is unreachable"}

    if isinstance(data, list):
        asked = "0" + local_number.replace(local_number[-4:], "xxxx")
        for voip in data:
            if voip.get("number") == asked:
                return {
                    "found": True,
                    "number_range": voip.get("number", ""),
                    "city": voip.get("city", ""),
                    "zip_code": voip.get("zipCode", ""),
                }
    return {"found": False}


# ─────────────────────────────────────────────
# OSINT FOOTPRINTS (Google dork URLs)
# ─────────────────────────────────────────────

def build_osint_urls(number_obj):
    n = number_obj["default"]
    intl = number_obj["international"]
    country_code = number_obj["countryCode"]

    def dork_url(q):
        return "https://www.google.com/search?q=" + requests.utils.quote(q)

    individual_urls = []
    for dork in INDIVIDUALS:
        if dork["dialCode"] is None or dork["dialCode"] == country_code:
            q = replace_variables(dork["request"], number_obj)
            individual_urls.append({"site": dork["site"], "url": dork_url(q)})

    reputation_urls = []
    for dork in REPUTATION:
        q = replace_variables(dork["request"], number_obj)
        reputation_urls.append({"title": dork["title"], "url": dork_url(q)})

    social_urls = []
    for dork in SOCIAL_MEDIAS:
        q = replace_variables(dork["request"], number_obj)
        social_urls.append({"site": dork["site"], "url": dork_url(q)})

    disposable_urls = []
    for dork in DISPOSABLE_PROVIDERS:
        q = replace_variables(dork["request"], number_obj)
        disposable_urls.append({"site": dork["site"], "url": dork_url(q)})

    return {
        "scan_411": "https://www.411.com/phone/{}".format(
            intl.replace("+", "").replace(" ", "-")
        ),
        "scamcallfighters": "http://www.scamcallfighters.com/search-phone-{}.html".format(n),
        "truepeoplesearch": (
            "https://www.truepeoplesearch.com/results?phoneno={}".format(
                intl.replace(" ", "")
            )
            if country_code == "+1" else None
        ),
        "web_search_url": dork_url('{} OR "{}" OR "{}"'.format(n, n, intl)),
        "doc_search_url": dork_url(
            '(ext:doc OR ext:pdf OR ext:xls) AND ("{}" OR "{}")'.format(intl, number_obj["local"])
        ),
        "individuals": individual_urls,
        "reputation": reputation_urls,
        "social_media": social_urls,
        "disposable_providers": disposable_urls,
    }


# ─────────────────────────────────────────────
# FLASK ROUTES
# ─────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name": "PhoneInfoga API",
        "version": "1.0.0",
        "endpoints": {
            "GET /scan?number=+91XXXXXXXXXX": "Full phone scan (local + numverify + ovh + osint)",
            "GET /local?number=+91XXXXXXXXXX": "Local scan only",
            "GET /numverify?number=+91XXXXXXXXXX": "Numverify.com scan",
            "GET /ovh?number=+91XXXXXXXXXX": "OVH VoIP scan",
            "GET /osint?number=+91XXXXXXXXXX": "OSINT search URLs",
        }
    })


@app.route("/scan", methods=["GET"])
def full_scan():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({"error": "Missing ?number= parameter"}), 400

    local = local_scan(number)
    if not local or "error" in local:
        return jsonify({"error": "Invalid or unrecognized phone number"}), 400

    return jsonify({
        "local": local,
        "numverify": numverify_scan(local["default"]),
        "ovh": ovh_scan(local["local"], local["countryIsoCode"]),
        "osint": build_osint_urls(local),
    })


@app.route("/local", methods=["GET"])
def local_only():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({"error": "Missing ?number= parameter"}), 400
    data = local_scan(number)
    if not data or "error" in data:
        return jsonify({"error": "Invalid phone number"}), 400
    return jsonify(data)


@app.route("/numverify", methods=["GET"])
def numverify_only():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({"error": "Missing ?number= parameter"}), 400
    local = local_scan(number)
    if not local or "error" in local:
        return jsonify({"error": "Invalid phone number"}), 400
    return jsonify(numverify_scan(local["default"]))


@app.route("/ovh", methods=["GET"])
def ovh_only():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({"error": "Missing ?number= parameter"}), 400
    local = local_scan(number)
    if not local or "error" in local:
        return jsonify({"error": "Invalid phone number"}), 400
    return jsonify(ovh_scan(local["local"], local["countryIsoCode"]))


@app.route("/osint", methods=["GET"])
def osint_only():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({"error": "Missing ?number= parameter"}), 400
    local = local_scan(number)
    if not local or "error" in local:
        return jsonify({"error": "Invalid phone number"}), 400
    return jsonify(build_osint_urls(local))


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
