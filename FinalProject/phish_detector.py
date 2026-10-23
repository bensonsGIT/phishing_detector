import re
import sys
import FinalProject.phrases as phrases
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

from bs4 import BeautifulSoup  # pip install beautifulsoup4

# --- 1. Weighted phrase list (replace/extend by loading your dataset) -------
# Higher weight = stronger phishing signal.
PHRASES = phrases.PHRASES

THRESHOLD_PHISHING = 100
THRESHOLD_SUSPICIOUS = 30


# --- 2. Parsing --------------------------------------------------------------
def parse_eml(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return extract_parts(msg)


def extract_parts(msg):
    """Return dict with sender, reply_to, subject, text, html."""
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    return {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "subject": msg.get("Subject", ""),
        "text": text_part.get_content() if text_part else "",
        "html": html_part.get_content() if html_part else "",
    }


def parse_pasted(raw_text):
    return {"from": "", "reply_to": "", "subject": "", "text": raw_text, "html": ""}


# --- 3. Checks ---------------------------------------------------------------
def domain_of(address):
    addr = parseaddr(address)[1]
    return addr.split("@")[-1].lower() if "@" in addr else ""


def phrase_score(body):
    body = body.lower()
    hits = [(p, w) for p, w in PHRASES.items() if p in body]
    return sum(w for _, w in hits), [p for p, _ in hits]


def link_mismatches(html):
    """Links where the visible text looks like a URL but points elsewhere."""
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


# --- 4. Scoring --------------------------------------------------------------
def analyze(email_data):
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
        score += 3
        reasons.append(f"Sender domain ({from_dom}) differs from Reply-To ({reply_dom})")

    mism = link_mismatches(email_data["html"])
    if mism:
        score += 4
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