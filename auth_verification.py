"""Independent SPF, DKIM, and DMARC checks for MailSentry.

DNS-backed checks use short timeouts. Message headers such as Authentication-
Results are deliberately not inputs to these verification routines.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Any, Callable


DNS_TIMEOUT = 2.0
SPF_QUERY_TIMEOUT = 8.0
MAX_DKIM_SIGNATURES = 8
DKIM_TAG = re.compile(r"(?:^|;)\s*([a-z])\s*=\s*([^;\s]+)", re.IGNORECASE)


@dataclass(frozen=True)
class SMTPAuthContext:
    """SMTP facts supplied by a trusted receiving MTA, never inferred from EML."""

    connecting_ip: str | None = None
    envelope_sender: str | None = None
    helo_identity: str | None = None
    trusted: bool = False


class DNSNoRecord(Exception):
    """The requested DNS record does not exist."""


class DNSTemporaryFailure(Exception):
    """A DNS request could not complete temporarily."""


def _result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, "reason": reason, **extra}


def _default_spf_check(**kwargs: Any) -> tuple[str, str]:
    import spf

    return spf.check2(**kwargs)


def verify_spf(
    context: SMTPAuthContext | None,
    checker: Callable[..., tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Evaluate SPF only from complete SMTP transaction inputs marked trusted."""
    if context is None or not context.trusted:
        return _result("NOT_EVALUATED", "Trusted SMTP connection inputs were not supplied.")
    if context.connecting_ip is None or context.envelope_sender is None or not context.helo_identity:
        return _result("NOT_EVALUATED", "Connecting IP, envelope sender, and HELO identity are all required.")
    try:
        ipaddress.ip_address(context.connecting_ip)
    except ValueError:
        return _result("NOT_EVALUATED", "The trusted SMTP connecting IP is invalid.")

    try:
        check = checker or _default_spf_check
        status, _explanation = check(
            i=context.connecting_ip,
            s=context.envelope_sender,
            h=context.helo_identity,
            timeout=DNS_TIMEOUT,
            querytime=SPF_QUERY_TIMEOUT,
        )
    except ImportError:
        return _result("NOT_EVALUATED", "SPF verification dependency is not installed.")
    except Exception as error:
        # spf3 exposes TempError/PermError; only the temporary error is network-related.
        error_type = type(error).__name__.lower()
        if any(token in error_type for token in ("temp", "timeout", "dns", "network", "socket")):
            return _result("TEMPERROR", "SPF DNS evaluation did not complete in time.")
        return _result("PERMERROR", "The SPF input or policy evaluation was invalid.")

    status = str(status).lower()
    if status not in {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}:
        return _result("PERMERROR", "The SPF library returned an unsupported result.")
    return _result(status.upper(), f"SPF evaluated from trusted SMTP inputs: {status.upper()}.")


def resolve_txt(name: str | bytes, timeout: float = DNS_TIMEOUT) -> bytes:
    """Resolve TXT records with a bounded dnspython lifetime."""
    try:
        import dns.exception
        import dns.resolver

        query_name = name.decode("ascii") if isinstance(name, bytes) else name
        answers = dns.resolver.resolve(query_name, "TXT", lifetime=timeout)
        records = [b"".join(chunk for chunk in answer.strings) for answer in answers]
        if not records:
            raise DNSNoRecord
        if len(records) > 1:
            raise ValueError("multiple TXT records")
        return records[0]
    except DNSNoRecord:
        raise
    except ImportError:
        raise
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        raise DNSNoRecord from None
    except Exception as error:
        # A record-set ambiguity is permanent; resolver/network errors are temporary.
        if isinstance(error, ValueError) and str(error) == "multiple TXT records":
            raise
        raise DNSTemporaryFailure from None


def _signature_tags(value: str) -> dict[str, str]:
    return {name.lower(): tag_value for name, tag_value in DKIM_TAG.findall(value)}


def _default_dkim_factory(raw_message: bytes) -> Any:
    import dkim

    return dkim.DKIM(raw_message, timeout=DNS_TIMEOUT)


def verify_dkim(
    raw_message: bytes | None,
    dns_lookup: Callable[[str | bytes, float], bytes] | None = None,
    verifier_factory: Callable[[bytes], Any] | None = None,
) -> dict[str, Any]:
    """Verify DKIM signatures against their DNS public keys using dkimpy."""
    if raw_message is None:
        return _result("NOT_EVALUATED", "Original RFC 5322 message bytes were not supplied.", signatures=[])
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    signatures = message.get_all("DKIM-Signature", [])
    if not signatures:
        return _result("NONE", "No DKIM-Signature header is present.", signatures=[])

    signature_tags = [_signature_tags(str(signature)) for signature in signatures[:MAX_DKIM_SIGNATURES]]
    if all(not tags.get("s") or not tags.get("d") for tags in signature_tags):
        return _result("INVALID", "DKIM signatures are missing a selector or signing domain.", signatures=[])

    lookup = dns_lookup or resolve_txt
    try:
        factory = verifier_factory or _default_dkim_factory
        verifier = factory(raw_message)
    except ImportError:
        return _result("NOT_EVALUATED", "DKIM verification dependency is not installed.", signatures=[])
    except Exception:
        return _result("INVALID", "The DKIM verifier rejected the message format.", signatures=[])

    outcomes: list[dict[str, str]] = []
    for index, tags in enumerate(signature_tags):
        selector, domain = tags.get("s"), tags.get("d")
        if not selector or not domain:
            outcomes.append({"status": "INVALID", "reason": "The DKIM signature is missing a selector or signing domain."})
            continue
        query_name = f"{selector}._domainkey.{domain}."
        try:
            public_key = lookup(query_name, DNS_TIMEOUT)
        except ImportError:
            return _result("NOT_EVALUATED", "DNS verification dependency is not installed.", signatures=[])
        except DNSNoRecord:
            outcomes.append({"status": "MISSING_KEY", "reason": "No public key was found for a DKIM signature.", "domain": domain})
            continue
        except DNSTemporaryFailure:
            outcomes.append({"status": "TEMPERROR", "reason": "A DKIM public-key DNS lookup timed out or failed temporarily.", "domain": domain})
            continue
        except Exception:
            outcomes.append({"status": "INVALID", "reason": "The DKIM public-key DNS response was invalid.", "domain": domain})
            continue

        def cached_lookup(name: str | bytes, timeout: float = DNS_TIMEOUT, *, expected: str = query_name,
                          key: bytes = public_key) -> bytes:
            normalized = name.decode("ascii", errors="ignore") if isinstance(name, bytes) else name
            if normalized.rstrip(".").lower() == expected.rstrip(".").lower():
                return key
            return lookup(name, min(timeout, DNS_TIMEOUT))

        try:
            valid = bool(verifier.verify(idx=index, dnsfunc=cached_lookup))
        except DNSTemporaryFailure:
            outcomes.append({"status": "TEMPERROR", "reason": "A DKIM DNS lookup failed temporarily.", "domain": domain})
        except Exception:
            outcomes.append({"status": "INVALID", "reason": "The DKIM signature or public key is invalid.", "domain": domain})
        else:
            outcomes.append({
                "status": "PASS" if valid else "INVALID",
                "reason": "The DKIM signature verified." if valid else "The DKIM signature did not verify.",
                "domain": domain,
            })

    statuses = {item["status"] for item in outcomes}
    if "PASS" in statuses:
        overall = "PASS"
    elif "TEMPERROR" in statuses:
        overall = "TEMPERROR"
    elif "INVALID" in statuses:
        overall = "INVALID"
    else:
        overall = "MISSING_KEY"
    if len(signatures) > MAX_DKIM_SIGNATURES:
        outcomes.append({"status": "NOT_EVALUATED", "reason": "DKIM signature evaluation limit reached."})
    return _result(overall, f"DKIM verification result: {overall}.", signatures=outcomes)


def _default_dmarc_lookup(domain: str) -> tuple[str, dict[str, Any]]:
    from checkdmarc.dmarc import get_dmarc_record

    record = get_dmarc_record(domain, timeout=DNS_TIMEOUT, retries=0)
    parsed = record.get("parsed", {})
    tags = parsed.get("tags", {}) if isinstance(parsed, dict) else {}
    return str(record.get("location", domain)), tags


def _tag_value(tags: dict[str, Any], key: str, default: str) -> str:
    value = tags.get(key, {})
    if isinstance(value, dict):
        value = value.get("value", default)
    return str(value or default).lower()


def _default_organizational_domain(domain: str) -> str | None:
    from checkdmarc.utils import get_base_domain

    return get_base_domain(domain)


def _has_temporary_dns_cause(error: Exception) -> bool:
    seen: set[int] = set()
    pending: list[BaseException] = [error]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        name = type(current).__name__.lower()
        if any(token in name for token in ("timeout", "servfail", "nonameservers", "dnstemperror")):
            return True
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return False


def _aligned(from_domain: str, auth_domain: str | None, mode: str,
             organizational_domain: Callable[[str], str | None]) -> bool:
    if not auth_domain:
        return False
    from_domain = from_domain.rstrip(".").lower()
    auth_domain = auth_domain.rstrip(".").lower()
    if mode == "s":
        return from_domain == auth_domain
    try:
        from_org = organizational_domain(from_domain)
        auth_org = organizational_domain(auth_domain)
    except Exception:
        return from_domain == auth_domain
    if not from_org or not auth_org:
        return from_domain == auth_domain
    return from_org.lower() == auth_org.lower()


def verify_dmarc(
    headers: dict[str, str],
    spf_result: dict[str, Any],
    dkim_result: dict[str, Any],
    record_lookup: Callable[[str], tuple[str, dict[str, Any]]] | None = None,
    organizational_domain: Callable[[str], str | None] | None = None,
) -> dict[str, Any]:
    """Evaluate DMARC from the visible From domain and independent auth results."""
    from_values = [address.rsplit("@", 1)[1].lower().rstrip(".") for _, address in
                   getaddresses([headers.get("from", "")]) if "@" in address]
    if len(from_values) != 1:
        return _result("NOT_EVALUATED", "DMARC requires exactly one valid visible From domain.", aligned=False)
    from_domain = from_values[0]
    lookup = record_lookup or _default_dmarc_lookup
    org_domain = organizational_domain or _default_organizational_domain
    try:
        record_domain, tags = lookup(from_domain)
    except ImportError:
        return _result("NOT_EVALUATED", "DMARC verification dependency is not installed.", aligned=False)
    except Exception as error:
        error_name = type(error).__name__.lower()
        if _has_temporary_dns_cause(error):
            return _result("TEMPERROR", "The DMARC policy DNS lookup failed temporarily.", aligned=False)
        if "notfound" in error_name or "nxdomain" in error_name or "noanswer" in error_name:
            return _result("NONE", "No applicable DMARC policy was found.", aligned=False)
        if any(token in error_name for token in ("timeout", "dns", "nameserver", "servfail")):
            return _result("TEMPERROR", "The DMARC policy DNS lookup failed temporarily.", aligned=False)
        return _result("PERMERROR", "The DMARC policy was malformed or could not be parsed.", aligned=False)

    if not isinstance(tags, dict):
        return _result("PERMERROR", "The DMARC policy parser returned invalid data.", aligned=False)
    subdomain_policy = from_domain != str(record_domain).rstrip(".").lower()
    policy_value = _tag_value(tags, "sp", _tag_value(tags, "p", "none")) if subdomain_policy else _tag_value(tags, "p", "none")
    dkim_mode = _tag_value(tags, "adkim", "r")
    spf_mode = _tag_value(tags, "aspf", "r")
    dkim_aligned = False
    for signature in dkim_result.get("signatures", []):
        if signature.get("status") == "PASS":
            # Signing domains are kept internal and are not exported in reports.
            domain = signature.get("domain")
            dkim_aligned |= _aligned(from_domain, domain, dkim_mode, org_domain)
    spf_domain = spf_result.get("identity_domain")
    spf_aligned = spf_result.get("status") == "PASS" and _aligned(from_domain, spf_domain, spf_mode, org_domain)
    passed = dkim_aligned or spf_aligned
    if not passed and (spf_result.get("status") == "TEMPERROR" or dkim_result.get("status") == "TEMPERROR"):
        return _result("TEMPERROR", "DMARC could not complete because an SPF or DKIM check had a temporary error.",
                       aligned=False, policy=policy_value)
    if not passed and (spf_result.get("status") == "NOT_EVALUATED" or dkim_result.get("status") == "NOT_EVALUATED"):
        return _result("NOT_EVALUATED", "No aligned pass was found; at least one required authentication check was unavailable.",
                       aligned=False, policy=policy_value)
    return _result(
        "PASS" if passed else "FAIL",
        "At least one aligned SPF or DKIM identifier passed." if passed else
        "A DMARC policy exists, but neither SPF nor DKIM passed with an aligned identifier.",
        aligned=passed,
        policy=policy_value,
    )


def verify_message_authentication(
    headers: dict[str, str],
    raw_message: bytes | None = None,
    smtp_context: SMTPAuthContext | None = None,
    *,
    spf_checker: Callable[..., tuple[str, str]] | None = None,
    dns_lookup: Callable[[str | bytes, float], bytes] | None = None,
    dkim_verifier_factory: Callable[[bytes], Any] | None = None,
    dmarc_record_lookup: Callable[[str], tuple[str, dict[str, Any]]] | None = None,
    organizational_domain: Callable[[str], str | None] | None = None,
) -> dict[str, dict[str, Any]]:
    """Return privacy-safe independent results; never read Authentication-Results."""
    spf_result = verify_spf(smtp_context, spf_checker)
    if spf_result["status"] == "PASS" and smtp_context:
        envelope_identity = smtp_context.envelope_sender or smtp_context.helo_identity or ""
        spf_result["identity_domain"] = envelope_identity.rsplit("@", 1)[-1].lower()
    dkim_result = verify_dkim(raw_message, dns_lookup, dkim_verifier_factory)
    dmarc_result = verify_dmarc(headers, spf_result, dkim_result, dmarc_record_lookup, organizational_domain)
    spf_result.pop("identity_domain", None)
    dkim_public = {key: value for key, value in dkim_result.items() if key != "signatures"}
    dkim_public["signatures"] = [
        {"status": item["status"], "reason": item["reason"]}
        for item in dkim_result.get("signatures", [])
    ]
    return {"spf": spf_result, "dkim": dkim_public, "dmarc": dmarc_result}
