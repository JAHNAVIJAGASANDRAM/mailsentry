"""Small, offline .eml analyzer for MailSentry."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


RISKY_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".exe", ".iso", ".jar", ".js", ".jse",
    ".lnk", ".msi", ".ps1", ".scr", ".vbe", ".vbs",
}
URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
AUTH_RESULT_PATTERN = re.compile(r"(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


def parse_eml(path: str | Path) -> dict[str, Any]:
    """Parse an RFC 5322 message without following links or opening attachments."""
    source = Path(path)
    with source.open("rb") as message_file:
        message = BytesParser(policy=policy.default).parse(message_file)

    bodies: list[str] = []
    attachments: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
        elif part.get_content_type() == "text/plain":
            try:
                content = part.get_content()
            except (LookupError, UnicodeDecodeError):
                content = ""
            if isinstance(content, str):
                bodies.append(content)

    return {
        "source": source.name,
        "headers": {name.lower(): str(value) for name, value in message.items()},
        "body": "\n".join(bodies),
        "attachments": attachments,
    }


def detect_content(parsed: dict[str, Any]) -> list[dict[str, str]]:
    """Find reply-address mismatches, IP-literal URLs, and risky filenames."""
    findings: list[dict[str, str]] = []
    headers = parsed["headers"]
    from_addresses = [address.lower() for _, address in getaddresses([headers.get("from", "")]) if address]
    reply_addresses = [address.lower() for _, address in getaddresses([headers.get("reply-to", "")]) if address]
    if from_addresses and reply_addresses and not set(from_addresses).intersection(reply_addresses):
        findings.append({"rule": "reply_to_mismatch", "evidence": ", ".join(reply_addresses)})

    for url in URL_PATTERN.findall(parsed["body"]):
        candidate = url if "://" in url else "http://" + url
        host = (urlsplit(candidate).hostname or "").rstrip(".")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        findings.append({"rule": "raw_ip_url", "evidence": url})
        break

    risky = [name for name in parsed["attachments"] if Path(name).suffix.lower() in RISKY_EXTENSIONS]
    if risky:
        findings.append({"rule": "risky_attachment", "evidence": ", ".join(risky)})
    return findings


def parse_authentication(headers: dict[str, str]) -> dict[str, str]:
    """Read SPF, DKIM, and DMARC outcomes from Authentication-Results headers."""
    results = {method: "unavailable" for method in ("spf", "dkim", "dmarc")}
    for header in headers.get("authentication-results", "").splitlines():
        for method, status in AUTH_RESULT_PATTERN.findall(header):
            results[method.lower()] = status.lower()
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze an email message offline.")
    parser.add_argument("eml", help="Path to a .eml file")
    parser.add_argument("--json", dest="json_path", help="Write parsed data as JSON")
    args = parser.parse_args()
    result = parse_eml(args.eml)
    result["findings"] = detect_content(result)
    result["authentication"] = parse_authentication(result["headers"])
    print(json.dumps(result, indent=2))
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
