"""Explainable, text-only promotional spam heuristics for MailSentry.

These signals describe message patterns. They are not proof of fraud, and none
of them opens URLs or validates the claims made in a message.
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlsplit



CONTENT_RULES = {
    "urgency_scarcity": {
        "points": 1,
        "label": "Urgency or scarcity language",
        "explanation": "The message uses time pressure or limited-availability language to encourage a quick response.",
        "recommendation": "Take time to verify the offer and its deadline independently before responding.",
        "category": "promotional_spam",
    },
    "fee_based_program_promotion": {
        "points": 1,
        "label": "Fee-based internship or training promotion",
        "explanation": "The message promotes an internship or training program, mentions fees, and solicits an application; text alone cannot establish whether the offer was requested or legitimate.",
        "recommendation": "Confirm the provider, fee terms, and whether the offer was expected before applying or paying.",
        "category": "promotional_spam",
    },
    "repeated_calls_to_action": {
        "points": 1,
        "label": "Repeated calls to action",
        "explanation": "Multiple application, registration, or sign-up prompts repeat across the message.",
        "recommendation": "Treat repeated prompts as a promotional signal and verify the offer independently.",
        "category": "promotional_spam",
    },
    "duplicate_urls": {
        "points": 1,
        "label": "Repeated URL",
        "explanation": "The same HTTP(S) URL appears more than once in the message.",
        "recommendation": "Repeated links do not validate a destination; inspect it only through your approved security process.",
        "category": "promotional_spam",
    },
    "unverified_outcome_claims": {
        "points": 1,
        "label": "Unverified placement or certification claims",
        "explanation": "The message claims placement support or a third-party credential; MailSentry cannot verify those claims from email text.",
        "recommendation": "Confirm placement terms and credential authorization with the named organization through a known official channel.",
        "category": "promotional_spam",
    },
}

CONTENT_RULE_POINTS = {rule: details["points"] for rule, details in CONTENT_RULES.items()}

_URGENCY = re.compile(
    r"\b(?:act\s+fast|act\s+now|apply\s+immediately|last\s+chance|don't\s+miss\s+out|"
    r"do\s+not\s+miss\s+out|deadline\s+(?:is\s+)?(?:today|soon)|expires?\s+(?:today|soon))\b", re.I
)
_SCARCITY = re.compile(
    r"\b(?:limited\s+(?:spots?|seats?|places?|availability)|only\s+\d+\s+(?:spots?|seats?|places?)|"
    r"few\s+(?:spots?|seats?|places?)\s+(?:left|remain)|while\s+(?:spots?|seats?)\s+last)\b", re.I
)
_PROGRAM = re.compile(r"\b(?:internships?|training|bootcamps?|career\s+programs?)\b", re.I)
_FEE = re.compile(r"\b(?:fees?|tuition|paid\s+program|registration\s+charge|course\s+cost)\b", re.I)
_SOLICITATION = re.compile(
    r"\b(?:apply|register|enroll|sign\s+up|join|submit\s+(?:your\s+)?application)\b", re.I
)
_CTA = re.compile(
    r"\b(?:apply(?:\s+(?:now|today|immediately))?|register(?:\s+(?:now|today))?|"
    r"enroll(?:\s+(?:now|today))?|sign\s+up(?:\s+(?:now|today))?|"
    r"complete\s+(?:your\s+)?application|submit\s+(?:your\s+)?application|"
    r"secure\s+(?:your\s+)?(?:spot|place)|click\s+here)\b", re.I
)
_PLACEMENT = re.compile(
    r"\b(?:placement\s+support|job\s+placement|guaranteed\s+(?:job|placement)|"
    r"hiring\s+partners|career\s+placement)\b", re.I
)
_THIRD_PARTY_CREDENTIAL = re.compile(
    r"\b(?:[A-Z][A-Za-z0-9&.'’-]*\s+){1,3}(?:training|internship|project|course)\s+"
    r"(?:completion\s+)?certificates?\b"
)
_AUTHORITY_CREDENTIAL = re.compile(
    r"\b(?:(?:industry[- ]recognized|government[- ]approved|officially\s+accredited)\s+"
    r"(?:certificate|certification|credential|program)|(?:certified|accredited|recognized|"
    r"approved|endorsed|issued|awarded)\s+by\s+[A-Z][\w&.'’-]*(?:\s+[A-Z][\w&.'’-]*){0,3})\b", re.I
)
_URL = re.compile(r"\bhttps?://[^\s<>\"']+", re.I)


def _extract_urls(body: str) -> list[str]:
    return [match.rstrip(".,!?;:)]}") for match in _URL.findall(body)]


def analyze_content(subject: str, body: str, *, weights: dict[str, int] | None = None) -> list[dict[str, object]]:
    """Return at most one safe, explainable finding per promotional rule.

    ``weights`` is an optional caller-provided rule-weight override; the default
    scoring remains documented in ``CONTENT_RULES``.
    """
    text = f"{subject}\n{body}"
    findings: list[dict[str, object]] = []

    def add(rule: str, condition: bool) -> None:
        if condition:
            findings.append({"rule": rule, "category": CONTENT_RULES[rule]["category"]})

    add("urgency_scarcity", bool(_URGENCY.search(text) or _SCARCITY.search(text)))
    add("fee_based_program_promotion", bool(
        _PROGRAM.search(text) and _FEE.search(text) and _SOLICITATION.search(text)
    ))
    add("repeated_calls_to_action", len(_CTA.findall(text)) >= 2)

    urls = _extract_urls(body)
    normalized: list[str] = []
    for url in urls:
        try:
            normalized.append(urlsplit(url).geturl().rstrip(".").casefold())
        except ValueError:
            # Malformed URLs are handled by the existing URL rules; do not let
            # them suppress otherwise independent text analysis.
            continue
    add("duplicate_urls", any(count > 1 for count in Counter(normalized).values()))

    add("unverified_outcome_claims", bool(
        _PLACEMENT.search(text) or _THIRD_PARTY_CREDENTIAL.search(text) or _AUTHORITY_CREDENTIAL.search(text)
    ))
    if weights:
        for finding in findings:
            if finding["rule"] in weights:
                # Keep the override explicit in the result for configurable callers.
                finding["points"] = weights[str(finding["rule"])]
    return findings
