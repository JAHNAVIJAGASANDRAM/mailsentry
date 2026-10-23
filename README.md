# MailSentry

MailSentry is an offline `.eml` analyzer and an optional post-delivery Gmail triage worker. It uses Python 3.10+ and the standard library for analysis. Gmail integration is opt-in, uses Google's official API libraries, and requests only `https://www.googleapis.com/auth/gmail.modify`.

MailSentry is post-delivery mailbox triage, not an email gateway or a replacement for Gmail spam filtering. It does not send, delete, move, quarantine, or mark messages as read. It does not follow URLs or execute/open attachments. Live inbox integration is not enabled by the offline CLI.

## Offline analysis

Provide a local `.eml` file. In Windows PowerShell:

```powershell
python .\mailsentry.py .\samples\benign.eml
python .\mailsentry.py .\samples\suspicious.eml --json .\reports\suspicious.json --report .\reports\suspicious.md
python -m unittest discover -s tests
```

Terminal, JSON, and Markdown reports are generated from the same analysis. JSON and Markdown omit the message body, headers, addresses, raw URLs, and attachment filenames. Markdown includes the input filename. Scores are rule-based heuristics, not probabilities of compromise. Missing SPF, DKIM, or DMARC results are reported as unavailable, not failed.

## Rules and scoring

Each rule contributes at most once per message:

| Rule | Points |
| --- | ---: |
| Reply-To differs from From | +2 |
| URL host is a raw IPv4 or IPv6 address | +2 |
| Risky attachment extension (`.bat`, `.cmd`, `.com`, `.exe`, `.iso`, `.jar`, `.js`, `.jse`, `.lnk`, `.msi`, `.ps1`, `.scr`, `.vbe`, `.vbs`) | +3 |
| DMARC result is `fail` | +2 |
| SPF result is `fail` | +1 |

Risk bands are Low (0–1), Medium (2–3), and High (4+). DKIM is reported but does not add points.

## Optional Gmail worker

Install the worker's dependencies from the repository directory:

```powershell
python -m pip install -r requirements.txt
```

### Google Cloud and OAuth setup

1. Create or select a Google Cloud project and enable the **Gmail API**.
2. Configure the OAuth consent screen. For local testing, choose the appropriate user type and add the Gmail account as a **test user**.
3. Create an OAuth client with application type **Desktop app** and download its client JSON as `credentials.json` in the repository directory. Desktop clients are public clients; do not treat an embedded client secret as confidential.
4. Keep `credentials.json` private. On first worker startup, a browser opens for explicit Gmail authorization. The resulting `token.json` is stored locally and ignored by Git. Revoke access in the Google account or delete the local token file to require authorization again.

Google setup references: [Enable the Gmail API](https://developers.google.com/workspace/gmail/api/quickstart/python), [OAuth for desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app), and [Gmail history synchronization](https://developers.google.com/workspace/gmail/api/guides/sync).

Start continuous polling (default interval: 60 seconds):

```powershell
python .\gmail_worker.py
```

Run one poll cycle, useful for checking setup:

```powershell
python .\gmail_worker.py --once
```

The one-shot command prints a privacy-safe summary with discovered, queued, processed, failed, and retry counts plus the report directory. An empty first run saves the initial checkpoint and reports that future Inbox arrivals will be monitored; it does not scan older mail. Configuration and authorization failures exit nonzero with a setup hint. Unexpected internal errors are reported by type only, and the message remains resumable.

Choose a different interval in seconds, then stop with `Ctrl+C`:

```powershell
python .\gmail_worker.py --interval 120
```

On first start, the worker saves the current Gmail history checkpoint; it processes Inbox additions after that checkpoint rather than scanning old mail. It follows history pagination with bounded requests and resumes unfinished pages on later polls. If Gmail has expired the saved history, the worker resets to the current checkpoint instead of scanning the whole mailbox; changes during an extended outage may therefore be missed.

The worker creates and applies one of `MailSentry/Low`, `MailSentry/Medium`, or `MailSentry/High` using the same offline score thresholds. Labels are added only; Gmail's Spam classification and all other labels are left untouched.

### Privacy and operational notes

- Message content is fetched only for newly observed Inbox additions and held in memory for analysis. It is not written to SQLite or logs.
- SQLite stores the Gmail message ID, status, attempt count, sanitized error code, and sync checkpoint so work can be deduplicated and resumed. OAuth credentials and tokens remain local.
- Reports use a hashed message identifier for filenames and omit message body, sender/recipient addresses, raw URLs, attachment filenames, and raw finding evidence.
- Generated reports, local OAuth files, SQLite state, and Python caches are ignored by Git. Review report storage and access on your machine because even sanitized risk results are operationally sensitive.
- Gmail modify scope permits reading messages and changing labels. The worker uses it to read new Inbox messages and add only its risk labels.

Troubleshooting: confirm the Gmail API is enabled, `credentials.json` is a Desktop app client, the authorizing account is listed as an OAuth test user, and the browser consent grants Gmail modify access. For revoked authorization, stop the worker, remove local `token.json`, and restart to authorize again. A 401/403 stops the worker rather than retrying indefinitely; transient rate-limit/server errors use bounded retries and resume on a later poll.
