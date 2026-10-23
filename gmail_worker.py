"""Opt-in Gmail mailbox triage worker. No Gmail calls occur on import."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import logging
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from mailsentry import build_report, parse_eml_bytes, render_markdown_report


SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
LABELS = {"Low": "MailSentry/Low", "Medium": "MailSentry/Medium", "High": "MailSentry/High"}
TRANSIENT_STATUSES = {408, 429, 500, 502, 503, 504}
LOGGER = logging.getLogger("mailsentry.gmail")


class WorkerError(Exception):
    """Sanitized worker failure with no API payload or message content."""


class ConfigurationError(WorkerError):
    pass


class AuthorizationError(WorkerError):
    pass


class NotFoundError(WorkerError):
    pass


class TransientApiError(WorkerError):
    pass


class PermanentApiError(WorkerError):
    pass


@dataclass
class PollResult:
    discovered: int = 0
    queued: int = 0
    processed: int = 0
    failures: int = 0
    retries: int = 0
    permanent_api_failures: int = 0
    initial_checkpoint: bool = False


def _http_status(error: Exception) -> int | None:
    response = getattr(error, "resp", None)
    status = getattr(response, "status", None)
    if status is None:
        status = getattr(error, "status_code", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _is_rate_limit_error(error: Exception) -> bool:
    content = getattr(error, "content", b"")
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="ignore")
    if not isinstance(content, str):
        return False
    try:
        details = json.loads(content).get("error", {})
    except (json.JSONDecodeError, AttributeError):
        return False
    reasons = {entry.get("reason") for entry in details.get("errors", []) if isinstance(entry, dict)}
    return bool(reasons & {"rateLimitExceeded", "userRateLimitExceeded"})


def _is_transport_error(error: Exception) -> bool:
    if isinstance(error, (TimeoutError, ConnectionError, OSError)):
        return True
    return error.__class__.__name__ in {"TransportError", "HttpLib2Error", "ServerNotFoundError"}


def create_gmail_service(
    credentials_path: str | Path = "credentials.json",
    token_path: str | Path = "token.json",
) -> Any:
    """Authorize this local desktop app and create a Gmail API client."""
    credentials_path = Path(credentials_path)
    token_path = Path(token_path)
    if not credentials_path.is_file():
        raise ConfigurationError("credentials.json is missing; follow the README OAuth setup first.")
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build

        credentials = None
        if token_path.is_file():
            try:
                candidate = Credentials.from_authorized_user_file(str(token_path), SCOPES)
                if candidate.has_scopes(SCOPES):
                    credentials = candidate
            except (OSError, ValueError):
                credentials = None

        if credentials and credentials.expired and credentials.refresh_token:
            try:
                credentials.refresh(Request())
            except Exception:
                # Expired or revoked grants require a fresh, user-approved desktop flow.
                credentials = None
        if not credentials or not credentials.valid:
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
            credentials = flow.run_local_server(port=0)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(credentials.to_json(), encoding="utf-8")
        return build("gmail", "v1", credentials=credentials, cache_discovery=False)
    except ConfigurationError:
        raise
    except Exception as error:
        # Do not include OAuth/library exception strings; they may contain local or secret data.
        raise ConfigurationError("Gmail OAuth setup failed; check credentials.json and authorize the test user.") from error


class StateStore:
    """Durable ID/status state only; message content is never written here."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS messages ("
            "message_id TEXT PRIMARY KEY, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, "
            "error_code TEXT, updated_at INTEGER NOT NULL)"
        )
        self.connection.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def get_setting(self, key: str) -> str | None:
        row = self.connection.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_setting(self, key: str, value: str | None) -> None:
        if value is None:
            self.connection.execute("DELETE FROM settings WHERE key=?", (key,))
        else:
            self.connection.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value))
        self.connection.commit()

    def queue(self, message_ids: list[str]) -> int:
        now = int(time.time())
        cursor = self.connection.executemany(
            "INSERT OR IGNORE INTO messages(message_id,status,updated_at) VALUES(?, 'pending', ?)",
            ((message_id, now) for message_id in message_ids if message_id),
        )
        self.connection.commit()
        return cursor.rowcount

    def unfinished(self, limit: int) -> list[str]:
        rows = self.connection.execute(
            "SELECT message_id FROM messages WHERE status IN ('pending','processing','retry') "
            "ORDER BY updated_at, message_id LIMIT ?", (limit,)
        ).fetchall()
        return [row[0] for row in rows]

    def status(self, message_id: str) -> str | None:
        row = self.connection.execute("SELECT status FROM messages WHERE message_id=?", (message_id,)).fetchone()
        return row[0] if row else None

    def _set_message(self, message_id: str, status: str, error_code: str | None = None, increment: bool = False) -> None:
        self.connection.execute(
            "UPDATE messages SET status=?, error_code=?, attempts=attempts+?, updated_at=? WHERE message_id=?",
            (status, error_code, int(increment), int(time.time()), message_id),
        )
        self.connection.commit()

    def processing(self, message_id: str) -> None:
        self._set_message(message_id, "processing", increment=True)

    def retry(self, message_id: str, code: str) -> None:
        self._set_message(message_id, "retry", code)

    def complete(self, message_id: str) -> None:
        self._set_message(message_id, "complete")

    def ignore(self, message_id: str) -> None:
        self._set_message(message_id, "ignored")

    def fail(self, message_id: str, code: str) -> None:
        self._set_message(message_id, "failed", code)


class GmailWorker:
    def __init__(
        self,
        service: Any,
        state: StateStore,
        report_dir: str | Path = "reports/gmail",
        polling_interval: int = 60,
        max_pages: int = 10,
        page_size: int = 100,
        batch_size: int = 100,
        max_attempts: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if polling_interval < 1 or max_pages < 1 or not 1 <= page_size <= 500 or batch_size < 1:
            raise ValueError("Polling and request limits must be positive; page_size must be 1..500.")
        self.service = service
        self.state = state
        self.report_dir = Path(report_dir)
        self.polling_interval = polling_interval
        self.max_pages = max_pages
        self.page_size = page_size
        self.batch_size = batch_size
        self.max_attempts = max_attempts
        self.sleep = sleep
        self.label_ids: dict[str, str] = {}
        self._initial_checkpoint = False
        self._cycle_failures = 0
        self._cycle_retries = 0
        self._cycle_permanent_api_failures = 0

    def _execute(self, make_request: Callable[[], Any]) -> Any:
        for attempt in range(self.max_attempts):
            try:
                return make_request().execute()
            except Exception as error:
                status = _http_status(error)
                transport_error = _is_transport_error(error)
                if status is None and not transport_error:
                    raise
                rate_limited = status == 403 and _is_rate_limit_error(error)
                if rate_limited:
                    status = 429
                if status in {401, 403}:
                    raise AuthorizationError("Gmail authorization was rejected; reauthorize the OAuth test user.") from None
                if status == 404:
                    raise NotFoundError("Gmail resource is no longer available.") from None
                transient = status in TRANSIENT_STATUSES or transport_error
                if not transient:
                    raise PermanentApiError(f"Gmail API request failed (status {status or 'unknown'}).") from None
                if attempt + 1 == self.max_attempts:
                    raise TransientApiError(f"Gmail API temporarily unavailable (status {status or 'network'}).") from None
                self.sleep(min(30.0, 2.0 ** attempt))
        raise TransientApiError("Gmail API retry limit reached.")

    def _users(self) -> Any:
        return self.service.users()

    def ensure_labels(self) -> dict[str, str]:
        response = self._execute(lambda: self._users().labels().list(userId="me"))
        found = {label.get("name"): label.get("id") for label in response.get("labels", [])}
        for risk, name in LABELS.items():
            label_id = found.get(name)
            if not label_id:
                created = self._execute(lambda name=name: self._users().labels().create(
                    userId="me", body={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
                ))
                label_id = created["id"]
            self.label_ids[risk] = label_id
        return self.label_ids

    def _profile_history_id(self) -> str:
        profile = self._execute(lambda: self._users().getProfile(userId="me"))
        return str(profile["historyId"])

    def discover_new_messages(self) -> tuple[int, int]:
        """Queue Inbox additions through bounded, resumable Gmail history pages."""
        current_history_id = self._profile_history_id()
        cursor = self.state.get_setting("history_id")
        if cursor is None:
            self.state.set_setting("history_id", current_history_id)
            self._initial_checkpoint = True
            LOGGER.info("Gmail history checkpoint initialized; new Inbox arrivals will be monitored.")
            return 0, 0

        page_token = self.state.get_setting("history_page_token")
        last_history_id = cursor
        pages = 0
        discovered_ids: set[str] = set()
        newly_queued = 0
        while pages < self.max_pages:
            kwargs: dict[str, Any] = {
                "userId": "me", "startHistoryId": cursor, "historyTypes": ["messageAdded"],
                "maxResults": self.page_size,
            }
            if page_token:
                kwargs["pageToken"] = page_token
            try:
                response = self._execute(lambda kwargs=kwargs: self._users().history().list(**kwargs))
            except NotFoundError:
                # Gmail history expires; re-checkpoint rather than scan the full mailbox.
                self.state.set_setting("history_id", current_history_id)
                self.state.set_setting("history_page_token", None)
                LOGGER.warning("Gmail history checkpoint expired; monitoring resumes from the current checkpoint.")
                return len(discovered_ids), newly_queued

            message_ids: list[str] = []
            for item in response.get("history", []):
                for added in item.get("messagesAdded", []):
                    message = added.get("message", {})
                    message_id = message.get("id")
                    labels = message.get("labelIds")
                    if message_id and (labels is None or "INBOX" in labels):
                        message_ids.append(str(message_id))
            discovered_ids.update(message_ids)
            newly_queued += self.state.queue(message_ids)
            page_token = response.get("nextPageToken")
            self.state.set_setting("history_page_token", page_token)
            last_history_id = str(response.get("historyId", current_history_id))
            pages += 1
            if not page_token:
                self.state.set_setting("history_page_token", None)
                self.state.set_setting("history_id", last_history_id)
                return len(discovered_ids), newly_queued

        # The saved page token resumes the bounded scan on the next poll.
        return len(discovered_ids), newly_queued

    def _report_paths(self, message_id: str) -> tuple[Path, Path]:
        safe_id = hashlib.sha256(message_id.encode("utf-8")).hexdigest()
        return self.report_dir / f"{safe_id}.json", self.report_dir / f"{safe_id}.md"

    def _write_reports(self, message_id: str, report: dict[str, Any]) -> None:
        json_path, markdown_path = self._report_paths(message_id)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        markdown_path.write_text(render_markdown_report(report, "Gmail message"), encoding="utf-8")

    def _process_message(self, message_id: str) -> str:
        self.state.processing(message_id)
        try:
            metadata = self._execute(lambda: self._users().messages().get(
                userId="me", id=message_id, format="minimal"
            ))
            if "INBOX" not in metadata.get("labelIds", []):
                self.state.ignore(message_id)
                return "ignored"

            raw_message = self._execute(lambda: self._users().messages().get(
                userId="me", id=message_id, format="raw"
            ))
            encoded = raw_message.get("raw")
            if not isinstance(encoded, str):
                self.state.fail(message_id, "malformed_message")
                LOGGER.warning("A Gmail message could not be parsed; processing skipped.")
                self._cycle_failures += 1
                return "failed"
            try:
                padded = encoded + "=" * (-len(encoded) % 4)
                message_bytes = base64.b64decode(padded, altchars=b"-_", validate=True)
                parsed = parse_eml_bytes(message_bytes, "Gmail message")
                report = build_report(parsed)
            except (ValueError, binascii.Error, LookupError, UnicodeError, TypeError):
                self.state.fail(message_id, "malformed_message")
                LOGGER.warning("A malformed Gmail message could not be analyzed; processing skipped.")
                self._cycle_failures += 1
                return "failed"

            self._write_reports(message_id, report)
            label_id = self.label_ids[report["risk_level"]]
            self._execute(lambda: self._users().messages().modify(
                userId="me", id=message_id, body={"addLabelIds": [label_id]}
            ))
            self.state.complete(message_id)
            return "processed"
        except AuthorizationError:
            self.state.retry(message_id, "authorization")
            raise
        except NotFoundError:
            self.state.fail(message_id, "not_found")
            LOGGER.info("A queued Gmail message is no longer available.")
            self._cycle_failures += 1
            return "failed"
        except TransientApiError:
            self.state.retry(message_id, "transient_api")
            LOGGER.warning("A Gmail message will be retried after a temporary API failure.")
            self._cycle_retries += 1
            return "retry"
        except PermanentApiError:
            self.state.fail(message_id, "api_permanent")
            LOGGER.warning("A Gmail message failed permanently with a sanitized API error.")
            self._cycle_failures += 1
            self._cycle_permanent_api_failures += 1
            return "failed"
        except OSError:
            self.state.retry(message_id, "filesystem")
            LOGGER.warning("A report could not be written; the message will be retried.")
            self._cycle_retries += 1
            return "retry"

    def process_pending(self) -> int:
        processed = 0
        for message_id in self.state.unfinished(self.batch_size):
            try:
                processed += int(self._process_message(message_id) == "processed")
            except AuthorizationError:
                raise
        return processed

    def poll_once(self) -> PollResult:
        self._initial_checkpoint = False
        self._cycle_failures = self._cycle_retries = self._cycle_permanent_api_failures = 0
        self.ensure_labels()
        discovered, queued = self.discover_new_messages()
        processed = self.process_pending()
        return PollResult(discovered, queued, processed, self._cycle_failures, self._cycle_retries,
                          self._cycle_permanent_api_failures, self._initial_checkpoint)

    def run(self, stop_event: threading.Event | None = None) -> None:
        stop_event = stop_event or threading.Event()
        LOGGER.info("MailSentry Gmail worker started; polling every %d seconds.", self.polling_interval)
        while not stop_event.is_set():
            try:
                self.poll_once()
            except AuthorizationError:
                LOGGER.error("Gmail authorization failed; worker stopped. Reauthorize and restart.")
                return
            except NotFoundError:
                LOGGER.error("A required Gmail API resource is unavailable; worker stopped.")
                return
            except TransientApiError:
                LOGGER.warning("Gmail API is temporarily unavailable; the next poll will retry.")
            except PermanentApiError:
                LOGGER.error("Gmail API rejected a request; worker stopped. Check API setup and permissions.")
                return
            stop_event.wait(self.polling_interval)
        LOGGER.info("MailSentry Gmail worker stopped.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Poll Gmail Inbox and apply MailSentry risk labels.")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds (default: 60)")
    parser.add_argument("--credentials", default="credentials.json", help="Local Google OAuth client JSON")
    parser.add_argument("--token", default="token.json", help="Local OAuth token file")
    parser.add_argument("--state", default="state/mailsentry.sqlite3", help="SQLite ID/status state file")
    parser.add_argument("--reports", default="reports/gmail", help="Directory for privacy-safe reports")
    parser.add_argument("--once", action="store_true", help="Run one poll cycle and exit")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stderr, force=True)
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    LOGGER.info("Starting MailSentry Gmail worker in %s mode.", "one-shot" if args.once else "continuous")
    try:
        service = create_gmail_service(args.credentials, args.token)
    except ConfigurationError as error:
        parser.exit(2, f"MailSentry: {error}\n")
    try:
        with StateStore(args.state) as state:
            worker = GmailWorker(service, state, args.reports, args.interval)
            if args.once:
                try:
                    result = worker.poll_once()
                except AuthorizationError as error:
                    parser.exit(2, f"MailSentry: {error}\n")
                except (NotFoundError, TransientApiError, PermanentApiError) as error:
                    parser.exit(1, f"MailSentry: Gmail polling failed: {error}\n")
                _print_poll_result(result, worker.report_dir)
                if result.failures or result.retries:
                    return 1
            else:
                try:
                    worker.run()
                except KeyboardInterrupt:
                    LOGGER.info("MailSentry Gmail worker stopped.")
    except (OSError, sqlite3.Error):
        parser.exit(2, "MailSentry: cannot access local Gmail state or report files. Check filesystem permissions.\n")
    except Exception as error:
        LOGGER.error("Unexpected internal error (%s); unfinished work remains resumable.", type(error).__name__)
        return 1
    return 0


def _print_poll_result(result: PollResult, report_dir: Path) -> None:
    print("\nMailSentry Gmail poll summary")
    print(f"New messages discovered: {result.discovered}")
    print(f"Messages queued: {result.queued}")
    print(f"Messages processed successfully: {result.processed}")
    print(f"Messages failed: {result.failures}")
    print(f"Messages scheduled for retry: {result.retries}")
    print(f"Reports directory: {report_dir}")
    if result.initial_checkpoint:
        print("No new messages were processed; the initial history checkpoint is saved for future arrivals.")
    elif result.discovered == 0 and result.processed == 0:
        print("No new Inbox messages found since the last history checkpoint.")


if __name__ == "__main__":
    raise SystemExit(main())
