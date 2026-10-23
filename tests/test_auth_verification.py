import unittest

from auth_verification import (
    DNSNoRecord,
    DNSTemporaryFailure,
    SMTPAuthContext,
    verify_dkim,
    verify_dmarc,
    verify_message_authentication,
    verify_spf,
)


SIGNED_MESSAGE = (
    b"From: Analyst <person@mail.example.org>\r\n"
    b"DKIM-Signature: v=1; d=sign.example.org; s=selector; h=from; bh=x; b=y\r\n"
    b"\r\nBody\r\n"
)


class FakeVerifier:
    def __init__(self, result=True, error=None):
        self.result = result
        self.error = error
        self.indices = []

    def verify(self, idx, dnsfunc):
        self.indices.append(idx)
        dnsfunc(b"selector._domainkey.sign.example.org.", timeout=1)
        if self.error:
            raise self.error
        return self.result


class AuthenticationVerificationTests(unittest.TestCase):
    def test_spf_requires_trusted_complete_smtp_inputs(self):
        called = []
        checker = lambda **kwargs: called.append(kwargs) or ("pass", "ignored")
        self.assertEqual(verify_spf(None, checker)["status"], "NOT_EVALUATED")
        self.assertEqual(verify_spf(SMTPAuthContext("192.0.2.2", "sender@example.org", "mx.example.org"), checker)["status"], "NOT_EVALUATED")
        self.assertEqual(verify_spf(SMTPAuthContext("192.0.2.2", "sender@example.org", None, True), checker)["status"], "NOT_EVALUATED")
        self.assertEqual(called, [])

    def test_spf_maps_supported_results_and_passes_real_context(self):
        context = SMTPAuthContext("192.0.2.2", "sender@example.org", "mx.example.org", True)
        for result in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
            calls = []
            verified = verify_spf(context, lambda **kwargs: calls.append(kwargs) or (result, "ignored"))
            self.assertEqual(verified["status"], result.upper())
            self.assertEqual(calls[0]["i"], "192.0.2.2")
            self.assertEqual(calls[0]["s"], "sender@example.org")
            self.assertEqual(calls[0]["h"], "mx.example.org")
            self.assertLessEqual(calls[0]["timeout"], 2)
            self.assertLessEqual(calls[0]["querytime"], 8)

    def test_dkim_missing_signature_malformed_signature_and_valid_signature(self):
        self.assertEqual(verify_dkim(b"From: x@example.org\n\nbody\n")["status"], "NONE")
        malformed = b"From: x@example.org\nDKIM-Signature: v=1; b=bad\n\nbody\n"
        self.assertEqual(verify_dkim(malformed)["status"], "INVALID")

        verifier = FakeVerifier(True)
        result = verify_dkim(
            SIGNED_MESSAGE,
            dns_lookup=lambda name, timeout: b"v=DKIM1; p=public",
            verifier_factory=lambda message: verifier,
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(verifier.indices, [0])

    def test_dkim_invalid_signature_missing_key_and_temporary_dns(self):
        invalid = verify_dkim(
            SIGNED_MESSAGE, dns_lookup=lambda *_: b"key",
            verifier_factory=lambda _: FakeVerifier(False),
        )
        self.assertEqual(invalid["status"], "INVALID")

        def missing(*_):
            raise DNSNoRecord
        self.assertEqual(verify_dkim(SIGNED_MESSAGE, dns_lookup=missing,
                                     verifier_factory=lambda _: FakeVerifier())["status"], "MISSING_KEY")

        def timeout(*_):
            raise DNSTemporaryFailure
        self.assertEqual(verify_dkim(SIGNED_MESSAGE, dns_lookup=timeout,
                                     verifier_factory=lambda _: FakeVerifier())["status"], "TEMPERROR")

    def test_dmarc_relaxed_and_strict_alignment(self):
        tags = {"p": {"value": "reject"}, "adkim": {"value": "r"}, "aspf": {"value": "r"}}
        record = lambda domain: ("example.org", tags)
        org = lambda domain: ".".join(domain.lower().split(".")[-2:])
        dkim = {"status": "PASS", "signatures": [{"status": "PASS", "domain": "sign.example.org"}]}
        spf = {"status": "NOT_EVALUATED"}
        result = verify_dmarc({"from": "Person <person@mail.example.org>"}, spf, dkim, record, org)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["aligned"])

        strict = {**tags, "adkim": {"value": "s"}}
        result = verify_dmarc({"from": "person@mail.example.org"}, {"status": "FAIL"}, dkim,
                              lambda domain: ("example.org", strict), org)
        self.assertEqual(result["status"], "FAIL")

    def test_dmarc_missing_malformed_temporary_and_actual_fail(self):
        headers = {"from": "person@example.org"}
        spf_fail = {"status": "FAIL"}
        dkim_fail = {"status": "INVALID", "signatures": []}

        class DMARCRecordNotFound(Exception):
            pass

        def missing(_):
            raise DMARCRecordNotFound()
        self.assertEqual(verify_dmarc(headers, spf_fail, dkim_fail, missing)["status"], "NONE")

        def missing_after_timeout(_):
            class DNSTimeout(Exception):
                pass
            try:
                raise DNSTimeout()
            except DNSTimeout as cause:
                error = DMARCRecordNotFound()
                error.__context__ = cause
                raise error
        self.assertEqual(verify_dmarc(headers, spf_fail, dkim_fail, missing_after_timeout)["status"], "TEMPERROR")

        class DMARCSyntaxError(Exception):
            pass

        def malformed(_):
            raise DMARCSyntaxError()
        self.assertEqual(verify_dmarc(headers, spf_fail, dkim_fail, malformed)["status"], "PERMERROR")

        class DNSTimeout(Exception):
            pass

        def timeout(_):
            raise DNSTimeout()
        self.assertEqual(verify_dmarc(headers, spf_fail, dkim_fail, timeout)["status"], "TEMPERROR")

        tags = {"p": {"value": "quarantine"}}
        failed = verify_dmarc(headers, spf_fail, dkim_fail, lambda _: ("example.org", tags))
        self.assertEqual(failed["status"], "FAIL")
        self.assertFalse(failed["aligned"])

    def test_unaligned_or_unavailable_inputs_do_not_fabricate_dmarc_failure(self):
        result = verify_message_authentication(
            {"from": "person@example.org", "authentication-results": "spf=fail; dmarc=fail"},
            SIGNED_MESSAGE,
            dmarc_record_lookup=lambda _: ("example.org", {"p": {"value": "reject"}}),
            dns_lookup=lambda *_: b"key",
            dkim_verifier_factory=lambda _: FakeVerifier(False),
        )
        self.assertEqual(result["spf"]["status"], "NOT_EVALUATED")
        self.assertEqual(result["dmarc"]["status"], "NOT_EVALUATED")
        self.assertNotIn("identity_domain", repr(result))
        self.assertNotIn("example.org", repr(result))


if __name__ == "__main__":
    unittest.main()
