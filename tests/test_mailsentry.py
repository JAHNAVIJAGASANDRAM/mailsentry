import json
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mailsentry import (
    build_report,
    extract_urls,
    parse_authentication,
    parse_eml,
    parse_eml_bytes,
    render_markdown_report,
    score_findings,
)


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
        markdown = render_markdown_report(report, parsed["source"])
        self.assertIn("Unavailable", markdown)
        self.assertIn("not counted as a failure", markdown)

    def test_reported_authentication_headers_do_not_count_as_verified_failures(self):
        report = build_report(parse_eml(ROOT / "samples" / "suspicious.eml"))
        rules = {finding["rule"] for finding in report["findings"]}
        self.assertEqual(rules, {"reply_to_mismatch", "raw_ip_url", "risky_attachment"})
        self.assertEqual(report["authentication"], {"spf": "fail", "dkim": "pass", "dmarc": "fail"})
        self.assertTrue(all(item["status"] == "NOT_EVALUATED" for item in report["verification"].values()))
        self.assertEqual((report["score"], report["risk_level"]), (7, "High"))

    def test_supplied_test_sample_gets_explainable_promotional_findings(self):
        report = build_report(parse_eml(ROOT / "samples" / "test.eml"))
        rules = {finding["rule"] for finding in report["findings"]}
        self.assertTrue({
            "urgency_scarcity", "fee_based_program_promotion", "repeated_calls_to_action",
            "duplicate_urls", "unverified_outcome_claims",
        }.issubset(rules))
        self.assertTrue(all(finding["category"] == "promotional_spam"
                            for finding in report["findings"] if finding["rule"] in rules))
        self.assertEqual(report["score"], 5)
        self.assertEqual(report["risk_level"], "High")
        self.assertTrue(all(finding["explanation"] for finding in report["findings"]))

    def test_legitimate_paid_training_ad_is_not_called_phishing(self):
        parsed = {
            "source": "training.eml",
            "headers": {"subject": "Optional paid Python training"},
            "body": "Our optional evening course has a tuition fee. Review the syllabus and register if it suits you.",
            "attachments": [],
        }
        report = build_report(parsed)
        self.assertEqual([item["rule"] for item in report["findings"]], ["fee_based_program_promotion"])
        self.assertEqual(report["findings"][0]["category"], "promotional_spam")
        self.assertEqual((report["score"], report["risk_level"]), (1, "Low"))

    def test_duplicate_urls_are_one_promotional_finding(self):
        parsed = {
            "headers": {"subject": "Course information"},
            "body": "Details: https://courses.example/info. Again: https://courses.example/info!",
            "attachments": [],
        }
        report = build_report(parsed)
        self.assertEqual([item["rule"] for item in report["findings"]], ["duplicate_urls"])
        self.assertEqual((report["score"], report["risk_level"]), (1, "Low"))

    def test_incomplete_headers_warn_without_inventing_authentication(self):
        malformed = parse_eml_bytes(b"From sender@example.org\nSubject: test\n\nA message body")
        self.assertTrue(malformed["warnings"])
        parsed = parse_eml_bytes(b"not a header\n\nA message body", "incomplete.eml")
        self.assertTrue(any("From header" in warning for warning in parsed["warnings"]))
        report = build_report(parsed, verify_auth=True, raw_message=b"not a header\n\nA message body")
        self.assertTrue(any("From header" in warning for warning in report["warnings"]))
        self.assertEqual(report["verification"]["spf"]["status"], "NOT_EVALUATED")
        self.assertEqual(report["verification"]["dmarc"]["status"], "NOT_EVALUATED")
        self.assertNotIn("spf_fail", {finding["rule"] for finding in report["findings"]})
        self.assertNotIn("dmarc_fail", {finding["rule"] for finding in report["findings"]})

    def test_independent_authentication_failures_are_scored_once(self):
        parsed = parse_eml(ROOT / "samples" / "suspicious.eml")
        verification = {
            "spf": {"status": "FAIL", "reason": "independent SPF check"},
            "dkim": {"status": "INVALID", "reason": "bad signature"},
            "dmarc": {"status": "FAIL", "reason": "no aligned pass"},
        }
        with patch("mailsentry.verify_message_authentication", return_value=verification):
            report = build_report(parsed, verify_auth=True, raw_message=b"message")
        rules = [finding["rule"] for finding in report["findings"]]
        self.assertEqual(rules.count("spf_fail"), 1)
        self.assertEqual(rules.count("dmarc_fail"), 1)
        self.assertEqual((report["score"], report["risk_level"]), (10, "High"))

    def test_cli_opt_in_uses_independent_results_for_reports(self):
        verification = {
            "spf": {"status": "NOT_EVALUATED", "reason": "trusted inputs unavailable"},
            "dkim": {"status": "PASS", "reason": "signature verified", "signatures": []},
            "dmarc": {"status": "PASS", "reason": "aligned DKIM pass", "aligned": True, "policy": "reject"},
        }
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            argv = ["mailsentry.py", str(ROOT / "samples" / "benign.eml"), "--verify-auth", "--json", str(json_path)]
            with patch("sys.argv", argv), patch("mailsentry.verify_message_authentication", return_value=verification) as verifier, \
                    redirect_stdout(io.StringIO()):
                from mailsentry import main
                main()
            exported = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(exported["verification"]["dkim"]["status"], "PASS")
        self.assertNotIn("domain", exported["verification"]["dkim"])
        self.assertNotIn("example.org", json.dumps(exported))
        self.assertEqual(verifier.call_args.args[1], (ROOT / "samples" / "benign.eml").read_bytes())

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
        markdown = render_markdown_report(report, "mail_[analyst]*.eml")
        for secret in ("secret@example.com", "private-token", "private-name.exe"):
            self.assertNotIn(secret, encoded)
            self.assertNotIn(secret, markdown)
        self.assertIn(r"mail\_\[analyst\]\*\.eml", markdown)
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

    def test_cli_exports_json_and_markdown_together(self):
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "json" / "suspicious.json"
            markdown_path = Path(directory) / "markdown" / "suspicious.md"
            result = subprocess.run(
                [sys.executable, str(ROOT / "mailsentry.py"), str(ROOT / "samples" / "suspicious.eml"),
                 "--json", str(json_path), "--report", str(markdown_path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
        self.assertEqual(data["risk_level"], "High")
        self.assertIn("Authentication", markdown)
        self.assertIn("Independent verification", markdown)
        self.assertIn("reported as received", markdown)
        self.assertIn("Findings", markdown)
        self.assertIn("Recommended actions", markdown)
        self.assertIn("+3 points", markdown)
        self.assertNotIn("invoice.exe", markdown)
        self.assertNotIn("192.0.2.45", markdown)
        self.assertNotIn("payroll@example.org", markdown)


if __name__ == "__main__":
    unittest.main()
