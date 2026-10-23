import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mailsentry import build_report, extract_urls, parse_authentication, parse_eml, score_findings


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
        self.assertEqual(score_findings([{"rule": "risky_attachment"}])[:2], (3, "Medium"))
        self.assertEqual(score_findings([{"rule": "reply_to_mismatch"}, {"rule": "raw_ip_url"}])[:2], (4, "High"))
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

    def test_html_only_and_malformed_message_and_urls(self):
        message = b"From: Sender <sender@example.org>\nTo: a@example.net, b@example.net\nContent-Type: text/html; charset=utf-8\n\n<a href='https://[2001:db8::1]:8443/path'>go</a> http://192.0.2.8:8080/path. http://[broken\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "odd.eml"
            path.write_bytes(message)
            parsed = parse_eml(path)
        self.assertIn("2001:db8::1", parsed["body"])
        self.assertIn("a@example.net", parsed["headers"]["to"])
        self.assertEqual(extract_urls(parsed["body"]), [
            "https://[2001:db8::1]:8443/path", "http://192.0.2.8:8080/path", "http://[broken",
        ])
        report = build_report(parsed)
        self.assertEqual([item["rule"] for item in report["findings"]], ["raw_ip_url"])

    def test_json_report_contains_explanations_but_no_message_values(self):
        message = b"From: sender@example.org\nReply-To: secret@example.com\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nhttps://192.0.2.33/private-token\n--x\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=private-name.exe\n\ndata\n--x--\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mail.eml"
            path.write_bytes(message)
            report = build_report(parse_eml(path))
        encoded = json.dumps(report)
        for secret in ("secret@example.com", "private-token", "private-name.exe"):
            self.assertNotIn(secret, encoded)
        self.assertTrue({"source", "headers", "body"}.isdisjoint(report))
        self.assertTrue(all(item["explanation"] for item in report["findings"]))

    def test_missing_headers_and_empty_message_are_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.eml"
            path.write_bytes(b"not a valid header\n\nbody")
            parsed = parse_eml(path)
        self.assertEqual(parsed["headers"], {})
        report = build_report(parsed)
        self.assertEqual((report["score"], report["risk_level"]), (0, "Low"))
        self.assertTrue(all(value == "unavailable" for value in report["authentication"].values()))

    def test_cli_creates_missing_report_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reports" / "benign-report.json"
            result = subprocess.run(
                [sys.executable, str(ROOT / "mailsentry.py"), str(ROOT / "samples" / "benign.eml"),
                 "--json", str(output)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["risk_level"], "Low")

    def test_cli_reports_invalid_output_path_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            blocker = Path(directory) / "file"
            blocker.write_text("not a directory", encoding="utf-8")
            output = blocker / "report.json"
            result = subprocess.run(
                [sys.executable, str(ROOT / "mailsentry.py"), str(ROOT / "samples" / "benign.eml"),
                 "--json", str(output)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("cannot write JSON report", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
