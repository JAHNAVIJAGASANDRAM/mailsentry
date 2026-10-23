import tempfile
import unittest
from pathlib import Path

from mailsentry import build_report, parse_authentication, parse_eml, score_findings


ROOT = Path(__file__).resolve().parents[1]


class MailSentryTests(unittest.TestCase):
    def test_benign_sample_parses_and_missing_auth_is_unavailable(self):
        parsed = parse_eml(ROOT / "samples" / "benign.eml")
        self.assertIn("meeting", parsed["body"].lower())
        self.assertEqual(parsed["attachments"], [])
        self.assertEqual(parse_authentication(parsed["headers"]), {
            "spf": "unavailable", "dkim": "unavailable", "dmarc": "unavailable",
        })
        report = build_report(parsed)
        self.assertEqual((report["score"], report["risk_level"]), (0, "Low"))

    def test_suspicious_sample_finds_content_and_auth_rules(self):
        report = build_report(parse_eml(ROOT / "samples" / "suspicious.eml"))
        rules = {finding["rule"] for finding in report["findings"]}
        self.assertEqual(rules, {
            "reply_to_mismatch", "raw_ip_url", "risky_attachment", "dmarc_fail", "spf_fail",
        })
        self.assertEqual(report["authentication"], {"spf": "fail", "dkim": "pass", "dmarc": "fail"})
        self.assertEqual((report["score"], report["risk_level"]), (10, "High"))

    def test_scoring_bands_and_deduplicates_rules(self):
        repeated = [
            {"rule": "reply_to_mismatch", "evidence": "a"},
            {"rule": "reply_to_mismatch", "evidence": "b"},
        ]
        self.assertEqual(score_findings(repeated)[:2], (2, "Medium"))
        self.assertEqual(score_findings([{"rule": "spf_fail"}])[:2], (1, "Low"))
        self.assertEqual(score_findings([
            {"rule": "risky_attachment"}, {"rule": "raw_ip_url"},
        ])[:2], (5, "High"))

    def test_parser_extracts_attachment_filename(self):
        message = b"""From: sender@example.org\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nhello\n--x\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=report.pdf\n\ncontent\n--x--\n"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attachment.eml"
            path.write_bytes(message)
            parsed = parse_eml(path)
        self.assertEqual(parsed["attachments"], ["report.pdf"])


if __name__ == "__main__":
    unittest.main()
