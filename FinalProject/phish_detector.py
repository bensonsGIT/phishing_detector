# Data from: https://github.com/rf-peixoto/phishing_pot
import re
import sys
import phrases as phrases
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from email.message import EmailMessage
from urllib.parse import urlparse
from bs4 import BeautifulSoup

PHRASES = phrases.PHRASES
THRESHOLD_PHISHING = 50
THRESHOLD_SUSPICIOUS = 20

def parse_eml(path: str) -> dict[str, str]:
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return extract_parts(msg)


def extract_parts(msg: EmailMessage) -> dict[str, str]:
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    return {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "subject": msg.get("Subject", ""),
        "text": text_part.get_content() if text_part else "",
        "auth": " ".join(msg.get_all("Authentication-Results", [])).lower(),
        "html": html_part.get_content() if html_part else "",
    }


def parse_pasted(raw_text: str) -> dict[str, str]:
    return {"from": "", "reply_to": "", "subject": "", "auth": "", "text": raw_text, "html": ""}


def domain_of(address: str) -> str:
    addr = parseaddr(address)[1]
    return addr.split("@")[-1].lower() if "@" in addr else ""


def phrase_score(body: str) -> tuple[int, list[str]]:
    body = body.lower()
    hits = [(p, w) for p, w in PHRASES.items() if p in body]
    return sum(w for _, w in hits), [p for p, _ in hits]


def link_mismatches(html: str) -> list[tuple[str, str]]:
    mismatches = []
    if not html:
        return mismatches
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        shown = a.get_text(strip=True)
        href_host = urlparse(a["href"]).netloc.lower()
        if re.match(r"^(https?://|www\.)", shown, re.I):
            shown_host = urlparse(
                shown if shown.startswith("http") else "http://" + shown
            ).netloc.lower()
            if shown_host and href_host and shown_host != href_host:
                mismatches.append((shown, a["href"]))
    return mismatches


def analyze(email_data: dict[str, str]) -> tuple[str, float, list[str]]:
    score = 0.0
    reasons = []

    body = " ".join([email_data["subject"], email_data["text"], BeautifulSoup(
        email_data["html"], "html.parser").get_text(" ") if email_data["html"] else ""])

    s, hits = phrase_score(body)
    if hits:
        score += s
        reasons.append(f"Suspicious phrases: {', '.join(hits)}")

    from_dom, reply_dom = domain_of(email_data["from"]), domain_of(email_data["reply_to"])
    if from_dom and reply_dom and from_dom != reply_dom:
        score += 25
        reasons.append(f"Sender domain ({from_dom}) differs from Reply-To ({reply_dom})")

    for check in ("spf", "dkim", "dmarc"):
        if f"{check}=fail" in email_data["auth"]:
            score += 30
            reasons.append(f"{check.upper()} check failed")
        elif f"{check}=none" in email_data["auth"] or f"{check}=permerror" in email_data["auth"]:
            score += 10
            reasons.append(f"No valid {check.upper()} record")

    mism = link_mismatches(email_data["html"])
    if mism:
        score += 15
        reasons.append(f"{len(mism)} link(s) where displayed URL != real URL")

    if score >= THRESHOLD_PHISHING:
        verdict = "LIKELY PHISHING"
    elif score >= THRESHOLD_SUSPICIOUS:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY LEGITIMATE"
    return verdict, score, reasons


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python phish_detector.py <email.eml>")
    verdict, score, reasons = analyze(parse_eml(sys.argv[1]))
    print(f"{verdict} (score {score:.1f})")
    for r in reasons:
        print(" -", r)