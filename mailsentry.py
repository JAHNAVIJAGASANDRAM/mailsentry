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

from auth_verification import SMTPAuthContext, verify_message_authentication


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
    "dmarc_fail": "Independent DMARC evaluation found no aligned SPF or DKIM pass under the sender domain's policy.",
    "spf_fail": "Independent SPF evaluation found that the trusted SMTP client was not authorized by the envelope sender's policy.",
}
RULE_LABELS = {
    "reply_to_mismatch": "Reply-To mismatch",
    "raw_ip_url": "URL uses a raw IP address",
    "risky_attachment": "Risky attachment type",
    "dmarc_fail": "DMARC failure",
    "spf_fail": "SPF failure",
}


def parse_eml(path: str | Path) -> dict[str, Any]:
    """Parse an RFC 5322 message without following links or opening attachments."""
    source = Path(path)
    with source.open("rb") as message_file:
        return parse_eml_bytes(message_file.read(), source.name)


def parse_eml_bytes(data: bytes, source: str = "message.eml") -> dict[str, Any]:
    """Parse RFC 5322 message bytes (for offline files or fetched MIME data)."""
    message = BytesParser(policy=policy.default).parsebytes(data)

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
        "source": source,
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


def build_report(
    parsed: dict[str, Any],
    *,
    verify_auth: bool = False,
    raw_message: bytes | None = None,
    smtp_context: SMTPAuthContext | None = None,
) -> dict[str, Any]:
    findings = detect_content(parsed)
    authentication = parse_authentication(parsed["headers"])
    verification = (
        verify_message_authentication(parsed["headers"], raw_message, smtp_context)
        if verify_auth else {
            method: {"status": "NOT_EVALUATED", "reason": "Independent authentication verification was not requested."}
            for method in ("spf", "dkim", "dmarc")
        }
    )
    if verification["dmarc"]["status"] == "FAIL":
        findings.append({"rule": "dmarc_fail", "evidence": "Independent DMARC result: fail"})
    if verification["spf"]["status"] == "FAIL":
        findings.append({"rule": "spf_fail", "evidence": "Independent SPF result: fail"})
    score, risk, recommendations = score_findings(findings)
    return {
        "findings": [
            {"rule": finding["rule"], "explanation": EXPLANATIONS[finding["rule"]],
             "points": RULE_POINTS[finding["rule"]]}
            for finding in findings
        ],
        "authentication": authentication,
        "verification": verification,
        "score": score,
        "risk_level": risk,
        "recommendations": recommendations,
    }


def escape_markdown(value: str) -> str:
    """Escape untrusted single-line text before inserting it into Markdown."""
    escaped: list[str] = []
    for character in " ".join(str(value).split()):
        if character in "\\`*_{}[]()#+-.!|>":
            escaped.append("\\" + character)
        elif character == "<":
            escaped.append("&lt;")
        elif character == "&":
            escaped.append("&amp;")
        else:
            escaped.append(character)
    return "".join(escaped)


def authentication_label(status: str) -> str:
    if status == "unavailable":
        return "Unavailable (no result present; not counted as a failure)"
    if status == "fail":
        return "FAILED"
    if status == "pass":
        return "Passed"
    return f"Result: {status}"


def verification_label(result: dict[str, Any]) -> str:
    status = result.get("status", "NOT_EVALUATED")
    reason = result.get("reason", "")
    return f"{status}: {reason}" if reason else status


def render_markdown_report(report: dict[str, Any], email_filename: str) -> str:
    """Render a privacy-safe human-readable Markdown analyst report."""
    lines = [
        "# MailSentry Analysis Report",
        "",
        f"**Email file:** {escape_markdown(email_filename)}",
        f"**Risk level:** {escape_markdown(report['risk_level'])}",
        f"**Score:** {report['score']} points",
        "",
        "> This score is a heuristic based on detected rules. It is not a probability of compromise or proof that a message is malicious.",
        "",
        "## Authentication",
        "",
        "These header values are reported as received. They are not trusted proof and do not affect the score.",
        "",
    ]
    for method, status in report["authentication"].items():
        lines.append(f"- **{method.upper()}:** {escape_markdown(authentication_label(status))}")

    lines.extend(["", "## Independent verification", ""])
    for method, result in report["verification"].items():
        lines.append(f"- **{method.upper()}:** {escape_markdown(verification_label(result))}")

    lines.extend(["", "## Findings", ""])
    if report["findings"]:
        for index, finding in enumerate(report["findings"], start=1):
            label = RULE_LABELS.get(finding["rule"], finding["rule"].replace("_", " ").title())
            lines.extend([
                f"{index}. **{escape_markdown(label)}** (+{finding['points']} points)",
                f"   - Why: {escape_markdown(finding['explanation'])}",
            ])
    else:
        lines.append("No indicators from the configured rules were found.")

    lines.extend(["", "## Recommended actions", ""])
    if report["recommendations"]:
        lines.extend(f"{index}. {escape_markdown(action)}" for index, action in enumerate(report["recommendations"], 1))
    else:
        lines.append("No rule-specific actions are recommended.")
    return "\n".join(lines) + "\n"


def write_output(path: str, content: str, description: str, parser: argparse.ArgumentParser) -> None:
    output_path = Path(path)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.exit(2, f"MailSentry: cannot write {description}: {error}\n")


def print_terminal_report(report: dict[str, Any], email_filename: str) -> None:
    print("=" * 60)
    print("MailSentry Analysis Report")
    print(f"Email file: {email_filename}")
    print(f"Risk level: {report['risk_level']} ({report['score']} points)")
    print("Note: This is a heuristic score, not a probability of compromise.")
    print("\nAuthentication-Results headers (reported, untrusted):")
    for method, status in report["authentication"].items():
        print(f"  {method.upper()}: {authentication_label(status)}")
    print("\nIndependent verification:")
    for method, result in report["verification"].items():
        print(f"  {method.upper()}: {verification_label(result)}")
    print("\nFindings:")
    if report["findings"]:
        for index, finding in enumerate(report["findings"], start=1):
            label = RULE_LABELS.get(finding["rule"], finding["rule"].replace("_", " ").title())
            print(f"  {index}. {label} (+{finding['points']} points)")
            print(f"     Why: {finding['explanation']}")
    else:
        print("  No indicators from the configured rules were found.")
    print("\nRecommended actions:")
    if report["recommendations"]:
        for index, action in enumerate(report["recommendations"], start=1):
            print(f"  {index}. {action}")
    else:
        print("  No rule-specific actions are recommended.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze an email message offline.")
    parser.add_argument("eml", help="Path to a .eml file")
    parser.add_argument("--json", dest="json_path", help="Write findings and risk summary to this JSON file")
    parser.add_argument("--report", dest="report_path", help="Write a human-readable Markdown report")
    parser.add_argument("--verify-auth", action="store_true",
                        help="Independently verify DKIM/DMARC using bounded DNS lookups; SPF needs trusted SMTP inputs")
    args = parser.parse_args()
    parsed = parse_eml(args.eml)
    raw_message = Path(args.eml).read_bytes() if args.verify_auth else None
    result = build_report(parsed, verify_auth=args.verify_auth, raw_message=raw_message)
    print_terminal_report(result, parsed["source"])
    if args.json_path:
        write_output(args.json_path, json.dumps(result, indent=2) + "\n", "JSON report", parser)
    if args.report_path:
        markdown = render_markdown_report(result, parsed["source"])
        write_output(args.report_path, markdown, "Markdown report", parser)


if __name__ == "__main__":
    main()
