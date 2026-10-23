import base64
import io
import json
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from gmail_worker import (
    SCOPES,
    AuthorizationError,
    ConfigurationError,
    GmailWorker,
    StateStore,
    create_gmail_service,
    main,
)


ROOT = Path(__file__).resolve().parents[1]


class FakeHttpError(Exception):
    def __init__(self, status, content=b""):
        self.resp = types.SimpleNamespace(status=status)
        self.content = content


class FakeRequest:
    def __init__(self, callback):
        self.callback = callback

    def execute(self):
        return self.callback()


class FakeLabels:
    def __init__(self):
        self.labels = []
        self.created = []
        self.list_error = None

    def list(self, **kwargs):
        def result():
            if self.list_error:
                raise self.list_error
            return {"labels": list(self.labels)}
        return FakeRequest(result)

    def create(self, **kwargs):
        body = kwargs["body"]
        label = {"id": f"label-{len(self.created)}", "name": body["name"]}
        self.labels.append(label)
        self.created.append(label)
        return FakeRequest(lambda: label)


class FakeMessages:
    def __init__(self, raw_messages):
        self.raw_messages = raw_messages
        self.modified = []
        self.inbox = set(raw_messages)
        self.deleted = set()
        self.invalid_raw_ids = set()
        self.modify_failures = 0
        self.modify_error = None

    def get(self, **kwargs):
        message_id = kwargs["id"]
        if message_id in self.deleted:
            return FakeRequest(lambda: (_ for _ in ()).throw(FakeHttpError(404)))
        if kwargs["format"] == "minimal":
            return FakeRequest(lambda: {"id": message_id, "labelIds": ["INBOX"] if message_id in self.inbox else []})
        if message_id in self.invalid_raw_ids:
            return FakeRequest(lambda: {"id": message_id, "raw": "**invalid-base64**"})
        encoded = base64.urlsafe_b64encode(self.raw_messages[message_id]).decode("ascii").rstrip("=")
        return FakeRequest(lambda: {"id": message_id, "raw": encoded})

    def modify(self, **kwargs):
        def apply():
            if self.modify_error:
                raise self.modify_error
            if self.modify_failures:
                self.modify_failures -= 1
                raise FakeHttpError(503)
            self.modified.append((kwargs["id"], kwargs["body"]["addLabelIds"]))
            return {}
        return FakeRequest(apply)


class FakeHistory:
    def __init__(self, pages=None):
        self.pages = pages or {}
        self.calls = []

    def list(self, **kwargs):
        self.calls.append(kwargs)
        token = kwargs.get("pageToken")
        return FakeRequest(lambda: self.pages[token])


class FakeUsers:
    def __init__(self, raw_messages, pages=None):
        self.label_resource = FakeLabels()
        self.message_resource = FakeMessages(raw_messages)
        self.history_resource = FakeHistory(pages)

    def labels(self):
        return self.label_resource

    def messages(self):
        return self.message_resource

    def history(self):
        return self.history_resource

    def getProfile(self, **kwargs):
        return FakeRequest(lambda: {"historyId": "900"})


class FakeService:
    def __init__(self, raw_messages, pages=None):
        self.user_resource = FakeUsers(raw_messages, pages)

    def users(self):
        return self.user_resource


def history_page(message_ids, history_id, next_token=None):
    history_entry = {
        "messagesAdded": [
            {"message": {"id": message_id, "labelIds": ["INBOX"]}}
            for message_id in message_ids
        ]
    }
    response = {"history": [history_entry], "historyId": history_id}
    if next_token:
        response["nextPageToken"] = next_token
    return response


class GmailWorkerTests(unittest.TestCase):
    def test_configuration_requires_local_credentials_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ConfigurationError, "credentials.json is missing"):
                create_gmail_service(Path(directory) / "credentials.json", Path(directory) / "token.json")

    def test_oauth_uses_only_modify_scope_and_desktop_flow(self):
        class FakeCredentials:
            valid = True
            expired = False
            refresh_token = None

            @staticmethod
            def has_scopes(scopes):
                return scopes == SCOPES

            @staticmethod
            def to_json():
                return '{"test_token":"do-not-log"}'

        class FakeFlow:
            def run_local_server(self, **kwargs):
                self.run_args = kwargs
                return FakeCredentials()

            @classmethod
            def from_client_secrets_file(cls, filename, scopes):
                calls["flow"] = (filename, scopes)
                flow = cls()
                calls["flow_instance"] = flow
                return flow

        calls = {}
        packages = {}
        package_names = [
            "google", "google.auth", "google.auth.transport", "google.oauth2",
            "google_auth_oauthlib", "googleapiclient",
        ]
        for name in package_names:
            package = types.ModuleType(name)
            package.__path__ = []
            packages[name] = package
        requests_module = types.ModuleType("google.auth.transport.requests")
        requests_module.Request = type("Request", (), {})
        credentials_module = types.ModuleType("google.oauth2.credentials")
        credentials_module.Credentials = type(
            "Credentials", (), {"from_authorized_user_file": staticmethod(lambda *args: FakeCredentials())}
        )
        flow_module = types.ModuleType("google_auth_oauthlib.flow")
        flow_module.InstalledAppFlow = FakeFlow
        discovery_module = types.ModuleType("googleapiclient.discovery")
        discovery_module.build = lambda *args, **kwargs: calls.setdefault("build", (args, kwargs))
        packages.update({
            "google.auth.transport.requests": requests_module,
            "google.oauth2.credentials": credentials_module,
            "google_auth_oauthlib.flow": flow_module,
            "googleapiclient.discovery": discovery_module,
        })
        with tempfile.TemporaryDirectory() as directory:
            credentials_file = Path(directory) / "credentials.json"
            credentials_file.write_text("{}", encoding="utf-8")
            token_file = Path(directory) / "token.json"
            with patch.dict(sys.modules, packages):
                service = create_gmail_service(credentials_file, token_file)
            self.assertEqual(service, calls["build"])
            self.assertEqual(calls["flow"][1], ["https://www.googleapis.com/auth/gmail.modify"])
            self.assertEqual(calls["flow_instance"].run_args, {"port": 0})
            self.assertTrue(token_file.is_file())
            self.assertNotIn("do-not-log", repr(calls))

    def test_pagination_duplicates_labels_and_privacy_safe_reports(self):
        benign = (ROOT / "samples" / "benign.eml").read_bytes()
        suspicious = (ROOT / "samples" / "suspicious.eml").read_bytes()
        medium = b"From: A <a@example.org>\nReply-To: b@example.net\nContent-Type: text/plain\n\nmedium synthetic mail\n"
        raw = {"low-id": benign, "mid-id": medium, "high-id": suspicious}
        pages = {
            None: history_page(["low-id", "mid-id"], "901", "page-2"),
            "page-2": history_page(["high-id", "low-id"], "902"),
        }
        service = FakeService(raw, pages)
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "state.sqlite3")
            state.set_setting("history_id", "900")
            worker = GmailWorker(service, state, Path(directory) / "reports", sleep=lambda _: None)
            result = worker.poll_once()
            self.assertEqual(result.processed, 3)
            self.assertEqual((result.discovered, result.queued), (3, 3))
            users = service.user_resource
            self.assertEqual(len(users.history_resource.calls), 2)
            self.assertEqual(users.history_resource.calls[1]["pageToken"], "page-2")
            self.assertEqual(len(users.label_resource.created), 3)
            self.assertEqual({label["name"] for label in users.label_resource.created}, {
                "MailSentry/Low", "MailSentry/Medium", "MailSentry/High",
            })
            self.assertEqual(dict(users.message_resource.modified), {
                "low-id": ["label-0"], "mid-id": ["label-1"], "high-id": ["label-2"],
            })
            self.assertEqual({state.status(message_id) for message_id in raw}, {"complete"})
            report_files = list((Path(directory) / "reports").glob("*"))
            self.assertEqual(len(report_files), 6)
            report_text = "\n".join(path.read_text(encoding="utf-8") for path in report_files)
            for private_value in ("payroll@example.org", "account-update@external.example", "192.0.2.45", "invoice.exe", "Review your payroll immediately"):
                self.assertNotIn(private_value, report_text)
            self.assertEqual(state.get_setting("history_id"), "902")
            state.close()
            sqlite_bytes = (Path(directory) / "state.sqlite3").read_bytes()
            for private_value in (b"payroll@example.org", b"invoice.exe", b"Review your payroll"):
                self.assertNotIn(private_value, sqlite_bytes)

    def _run_once(self, directory, service):
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["gmail_worker.py", "--once", "--state", str(Path(directory) / "state.sqlite3"),
                "--reports", str(Path(directory) / "reports")]
        with patch.object(sys, "argv", argv), patch("gmail_worker.create_gmail_service", return_value=service), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_once_reports_empty_checkpoint_and_returns_success(self):
        with tempfile.TemporaryDirectory() as directory:
            code, output, logs = self._run_once(directory, FakeService({}))
            self.assertEqual(code, 0)
            self.assertIn("New messages discovered: 0", output)
            self.assertIn("Messages queued: 0", output)
            self.assertIn("No new messages were processed; the initial history checkpoint", output)
            self.assertIn("Reports directory:", output)
            self.assertIn("Starting MailSentry Gmail worker in one-shot mode", logs)

    def test_once_reports_processing_counts_and_writes_reports_and_label(self):
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "state.sqlite3")
            state.set_setting("history_id", "900")
            state.close()
            service = FakeService({"safe-id": (ROOT / "samples" / "benign.eml").read_bytes()},
                                  {None: history_page(["safe-id"], "901")})
            code, output, _ = self._run_once(directory, service)
            self.assertEqual(code, 0)
            self.assertIn("New messages discovered: 1", output)
            self.assertIn("Messages queued: 1", output)
            self.assertIn("Messages processed successfully: 1", output)
            self.assertIn("Messages failed: 0", output)
            self.assertIn("Messages scheduled for retry: 0", output)
            self.assertEqual(len(list((Path(directory) / "reports").glob("*"))), 2)
            self.assertEqual(len(service.user_resource.message_resource.modified), 1)

    def test_once_auth_failure_is_nonzero_and_does_not_log_error_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            service = FakeService({})
            service.user_resource.label_resource.list_error = FakeHttpError(403, b"private@example.org bearer-secret")
            stdout, stderr = io.StringIO(), io.StringIO()
            argv = ["gmail_worker.py", "--once", "--state", str(Path(directory) / "state.sqlite3")]
            with patch.object(sys, "argv", argv), patch("gmail_worker.create_gmail_service", return_value=service), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    main()
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("reauthorize", stderr.getvalue())
            self.assertNotIn("private@example.org", stderr.getvalue())
            self.assertNotIn("bearer-secret", stderr.getvalue())

    def test_once_global_transient_and_permanent_api_failures_are_nonzero(self):
        for failure, message in ((FakeHttpError(503), "temporarily unavailable"),
                                 (FakeHttpError(400), "status 400")):
            with self.subTest(status=failure.resp.status), tempfile.TemporaryDirectory() as directory:
                service = FakeService({})
                service.user_resource.label_resource.list_error = failure
                stdout, stderr = io.StringIO(), io.StringIO()
                argv = ["gmail_worker.py", "--once", "--state", str(Path(directory) / "state.sqlite3")]
                with patch.object(sys, "argv", argv), patch("gmail_worker.create_gmail_service", return_value=service), \
                        patch("gmail_worker.time.sleep", lambda _: None), redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        main()
                self.assertEqual(raised.exception.code, 1)
                self.assertIn(message, stderr.getvalue())

    def test_once_counts_per_message_retries_and_permanent_api_failures(self):
        for error, expected_status, count_label in (
            (FakeHttpError(503), "retry", "Messages scheduled for retry: 1"),
            (FakeHttpError(400), "failed", "Messages failed: 1"),
        ):
            with self.subTest(status=error.resp.status), tempfile.TemporaryDirectory() as directory:
                state = StateStore(Path(directory) / "state.sqlite3")
                state.set_setting("history_id", "900")
                state.close()
                service = FakeService({"mail-id": (ROOT / "samples" / "benign.eml").read_bytes()},
                                      {None: history_page(["mail-id"], "901")})
                service.user_resource.message_resource.modify_error = error
                stdout, stderr = io.StringIO(), io.StringIO()
                argv = ["gmail_worker.py", "--once", "--state", str(Path(directory) / "state.sqlite3"),
                        "--reports", str(Path(directory) / "reports")]
                with patch.object(sys, "argv", argv), patch("gmail_worker.create_gmail_service", return_value=service), \
                        patch("gmail_worker.time.sleep", lambda _: None), redirect_stdout(stdout), redirect_stderr(stderr):
                    code = main()
                self.assertEqual(code, 1)
                self.assertIn(count_label, stdout.getvalue())
                state = StateStore(Path(directory) / "state.sqlite3")
                self.assertEqual(state.status("mail-id"), expected_status)
                state.close()

    def test_unexpected_programming_error_is_not_swallowed(self):
        class BrokenService(FakeService):
            def users(self):
                raise RuntimeError("should not leak")
        with tempfile.TemporaryDirectory() as directory:
            stdout, stderr = io.StringIO(), io.StringIO()
            argv = ["gmail_worker.py", "--once", "--state", str(Path(directory) / "state.sqlite3")]
            with patch.object(sys, "argv", argv), patch("gmail_worker.create_gmail_service", return_value=BrokenService({})), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                code = main()
            self.assertEqual(code, 1)
            self.assertIn("Unexpected internal error (RuntimeError)", stderr.getvalue())
            self.assertNotIn("should not leak", stderr.getvalue())

    def test_interrupted_processing_resumes_and_duplicate_queue_is_unique(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            state = StateStore(path)
            state.queue(["message-id", "message-id"])
            state.processing("message-id")
            state.close()
            resumed = StateStore(path)
            self.assertEqual(resumed.unfinished(10), ["message-id"])
            resumed.queue(["message-id"])
            self.assertEqual(resumed.connection.execute("SELECT count(*) FROM messages").fetchone()[0], 1)
            self.assertEqual(resumed.connection.execute("SELECT attempts FROM messages").fetchone()[0], 1)
            resumed.close()

    def test_retries_transient_errors_and_stops_on_permission_failure(self):
        class SequenceRequest:
            def __init__(self, sequence):
                self.sequence = sequence

            def execute(self):
                outcome = self.sequence.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "state.sqlite3")
            delays = []
            worker = GmailWorker(FakeService({}), state, sleep=delays.append)
            quota_error = FakeHttpError(
                403,
                b'{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}',
            )
            request = SequenceRequest([FakeHttpError(503), quota_error, {"ok": True}])
            self.assertEqual(worker._execute(lambda: request), {"ok": True})
            self.assertEqual(delays, [1.0, 2.0])
            with self.assertRaises(AuthorizationError):
                worker._execute(lambda: SequenceRequest([FakeHttpError(403)]))
            self.assertEqual(delays, [1.0, 2.0])
            state.close()

    def test_deleted_and_malformed_messages_are_not_completed(self):
        raw = {"bad-message": b"not valid base64 data"}
        service = FakeService(raw)
        service.user_resource.message_resource.deleted.add("deleted-message")
        service.user_resource.message_resource.invalid_raw_ids.add("bad-message")
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "state.sqlite3")
            state.queue(["deleted-message", "bad-message"])
            worker = GmailWorker(service, state, Path(directory) / "reports", sleep=lambda _: None)
            worker.ensure_labels()
            self.assertEqual(worker.process_pending(), 0)
            self.assertEqual(state.status("deleted-message"), "failed")
            self.assertEqual(state.status("bad-message"), "failed")
            report_dir = Path(directory) / "reports"
            self.assertEqual(list(report_dir.glob("*")) if report_dir.exists() else [], [])
            state.close()

    def test_label_failure_retries_without_duplicate_reports(self):
        raw = {"message-id": (ROOT / "samples" / "benign.eml").read_bytes()}
        service = FakeService(raw)
        service.user_resource.message_resource.modify_failures = 3
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "state.sqlite3")
            state.queue(["message-id"])
            worker = GmailWorker(service, state, Path(directory) / "reports", sleep=lambda _: None)
            worker.ensure_labels()
            self.assertEqual(worker.process_pending(), 0)
            self.assertEqual(state.status("message-id"), "retry")
            report_dir = Path(directory) / "reports"
            self.assertEqual(len(list(report_dir.glob("*"))), 2)
            self.assertEqual(worker.process_pending(), 1)
            self.assertEqual(state.status("message-id"), "complete")
            self.assertEqual(len(list(report_dir.glob("*"))), 2)
            self.assertEqual(len(service.user_resource.message_resource.modified), 1)
            state.close()

    def test_verify_auth_option_passes_original_mime_to_independent_verifier(self):
        raw = {"message-id": (ROOT / "samples" / "benign.eml").read_bytes()}
        service = FakeService(raw)
        verification = {
            "spf": {"status": "NOT_EVALUATED", "reason": "SMTP inputs unavailable"},
            "dkim": {"status": "PASS", "reason": "signature verified", "signatures": []},
            "dmarc": {"status": "PASS", "reason": "aligned DKIM pass", "aligned": True, "policy": "reject"},
        }
        with tempfile.TemporaryDirectory() as directory:
            state = StateStore(Path(directory) / "state.sqlite3")
            state.queue(["message-id"])
            worker = GmailWorker(service, state, Path(directory) / "reports", verify_auth=True)
            worker.ensure_labels()
            with patch("mailsentry.verify_message_authentication", return_value=verification) as verifier:
                self.assertEqual(worker.process_pending(), 1)
            self.assertEqual(verifier.call_args.args[1], raw["message-id"])
            reports = list((Path(directory) / "reports").glob("*.json"))
            self.assertEqual(json.loads(reports[0].read_text(encoding="utf-8"))["verification"]["dkim"]["status"], "PASS")
            state.close()


if __name__ == "__main__":
    unittest.main()
