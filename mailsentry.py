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
RULE_POINTS = {
    "reply_to_mismatch": 2,
    "raw_ip_url": 2,
    "risky_attachment": 3,
    "dmarc_fail": 2,
    "spf_fail": 1,
}
RECOMMENDATIONS = {
    "reply_to_mismatch": "Verify the sender using a known contact method before replying.",
    "raw_ip_url": "Do not follow the URL; verify the destination through a trusted channel.",
    "risky_attachment": "Do not open the attachment; confirm it with the sender through a trusted channel.",
    "dmarc_fail": "Treat the sender domain as unauthenticated and verify the message independently.",
    "spf_fail": "Treat the sending server as unverified and verify the message independently.",
}
EXPLANATIONS = {
    "reply_to_mismatch": "The Reply-To address differs from the sender address.",
    "raw_ip_url": "A message URL uses an IP address instead of a domain name.",
    "risky_attachment": "An attachment uses a file extension commonly used for executable content.",
    "dmarc_fail": "The message reports a failed DMARC authentication result.",
    "spf_fail": "The message reports a failed SPF authentication result.",
}


def parse_eml(path: str | Path) -> dict[str, Any]:
    """Parse an RFC 5322 message without following links or opening attachments."""
    source = Path(path)
    with source.open("rb") as message_file:
        message = BytesParser(policy=policy.default).parse(message_file)

    plain_bodies: list[str] = []
    html_bodies: list[str] = []
    attachments: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
        elif part.get_content_type() in {"text/plain", "text/html"}:
            try:
                content = part.get_content()
            except (LookupError, UnicodeDecodeError):
                content = ""
            if isinstance(content, str):
                (plain_bodies if part.get_content_type() == "text/plain" else html_bodies).append(content)

    headers: dict[str, str] = {}
    for name, value in message.items():
        key = name.lower()
        headers[key] = f"{headers[key]}\n{value}" if key in headers else str(value)
    return {
        "source": source.name,
        "headers": headers,
        "body": "\n".join(plain_bodies or html_bodies),
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

    for url in extract_urls(parsed["body"]):
        candidate = url if "://" in url else "http://" + url
        try:
            host = (urlsplit(candidate).hostname or "").rstrip(".")
        except ValueError:
            continue
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


def extract_urls(body: str) -> list[str]:
    """Extract HTTP(S) and www-style links without requesting them."""
    return [url.rstrip(".,!?;:)]}") for url in URL_PATTERN.findall(body)]


def parse_authentication(headers: dict[str, str]) -> dict[str, str]:
    """Read SPF, DKIM, and DMARC outcomes from Authentication-Results headers."""
    results = {method: "unavailable" for method in ("spf", "dkim", "dmarc")}
    for header in headers.get("authentication-results", "").splitlines():
        for method, status in AUTH_RESULT_PATTERN.findall(header):
            results[method.lower()] = status.lower()
    return results


def score_findings(findings: list[dict[str, str]]) -> tuple[int, str, list[str]]:
    """Score each rule once and return its total, risk band, and actions."""
    rules = {finding["rule"] for finding in findings if finding["rule"] in RULE_POINTS}
    score = sum(RULE_POINTS[rule] for rule in rules)
    risk = "Low" if score <= 1 else "Medium" if score <= 3 else "High"
    recommendations = [RECOMMENDATIONS[rule] for rule in RULE_POINTS if rule in rules]
    return score, risk, recommendations


def build_report(parsed: dict[str, Any]) -> dict[str, Any]:
    findings = detect_content(parsed)
    authentication = parse_authentication(parsed["headers"])
    if authentication["dmarc"] == "fail":
        findings.append({"rule": "dmarc_fail", "evidence": "DMARC result: fail"})
    if authentication["spf"] == "fail":
        findings.append({"rule": "spf_fail", "evidence": "SPF result: fail"})
    score, risk, recommendations = score_findings(findings)
    return {
        "findings": [
            {"rule": finding["rule"], "explanation": EXPLANATIONS[finding["rule"]],
             "points": RULE_POINTS[finding["rule"]]}
            for finding in findings
        ],
        "authentication": authentication,
        "score": score,
        "risk_level": risk,
        "recommendations": recommendations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze an email message offline.")
    parser.add_argument("eml", help="Path to a .eml file")
    parser.add_argument("--json", dest="json_path", help="Write findings and risk summary to this JSON file")
    args = parser.parse_args()
    parsed = parse_eml(args.eml)
    result = build_report(parsed)
    print(f"MailSentry report: {parsed['source']}")
    print(f"Risk: {result['risk_level']} ({result['score']} points)")
    print("Authentication: " + ", ".join(f"{key.upper()} {value}" for key, value in result["authentication"].items()))
    if result["findings"]:
        print("Findings:")
        for finding in result["findings"]:
            print(f"  - {finding['rule']} (+{finding['points']}): {finding['explanation']}")
    else:
        print("Findings: none")
    if result["recommendations"]:
        print("Recommendations:")
        for recommendation in result["recommendations"]:
            print(f"  - {recommendation}")
    if args.json_path:
        report_path = Path(args.json_path)
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        except (OSError, ValueError) as error:
            parser.exit(2, f"MailSentry: cannot write JSON report: {error}\n")


if __name__ == "__main__":
    main()
