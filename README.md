# MailSentry

MailSentry is a local `.eml` analyzer and an optional post-delivery Gmail triage worker. Core parsing and content checks use Python 3.10+ and the standard library. Independent SPF, DKIM, and DMARC checks are opt-in and use DNS; Gmail integration is also opt-in, uses Google's official API libraries, and requests only `https://www.googleapis.com/auth/gmail.modify`.

MailSentry is post-delivery mailbox triage, not an email gateway or a replacement for Gmail spam filtering. It does not send, delete, move, quarantine, or mark messages as read. It does not follow URLs or execute/open attachments. Live inbox integration is not enabled by the offline CLI.

## Offline analysis

Provide a local `.eml` file. In Windows PowerShell:

```powershell
python .\mailsentry.py .\samples\benign.eml
python .\mailsentry.py .\samples\suspicious.eml --json .\reports\suspicious.json --report .\reports\suspicious.md
python -m unittest discover -s tests
```

Terminal, JSON, and Markdown reports are generated from the same analysis. JSON and Markdown omit the message body, headers, addresses, raw URLs, and attachment filenames. Markdown includes the input filename. Scores are rule-based heuristics, not probabilities of compromise. `Authentication-Results` values are shown as untrusted reported headers and never prove authentication or affect scoring. Independent checks are not run by default.

Run independent DKIM and DMARC checks with bounded DNS requests:

```powershell
python .\mailsentry.py .\samples\suspicious.eml --verify-auth --json .\reports\verified.json --report .\reports\verified.md
```

The verifier checks DKIM signatures against DNS public keys, looks up and parses the applicable DMARC policy, and evaluates SPF/DKIM alignment. Imported `.eml` files and Gmail API messages do not contain trusted SMTP transaction data, so SPF is reported as `NOT_EVALUATED`; MailSentry never infers the connecting IP, envelope sender, or HELO identity from message headers. A future trusted receiving-MTA integration can pass those values through the `SMTPAuthContext` interface. DMARC is only reported as a failure when policy and available independent checks establish that no aligned identifier passed; absent SMTP inputs or temporary DNS errors remain not evaluated/temporary.

## Rules and scoring

Each rule contributes at most once per message:

| Rule | Points |
| --- | ---: |
| Reply-To differs from From | +2 |
| URL host is a raw IPv4 or IPv6 address | +2 |
| Risky attachment extension (`.bat`, `.cmd`, `.com`, `.exe`, `.iso`, `.jar`, `.js`, `.jse`, `.lnk`, `.msi`, `.ps1`, `.scr`, `.vbe`, `.vbs`) | +3 |
| Independently verified DMARC result is `FAIL` | +2 |
| Independently verified SPF result is `FAIL` | +1 |
| Urgency or scarcity wording | +1 |
| Fee-based internship/training promotion with application solicitation | +1 |
| Repeated application or registration calls to action | +1 |
| Same HTTP(S) URL repeated | +1 |
| Placement-support or third-party certification claim that cannot be verified from message text | +1 |

Risk bands are Low (0–1), Medium (2–3), and High (4+). DKIM is reported but does not add points. Each rule is counted once. Reported header failures alone never contribute points.

The content rules are separate promotional-spam indicators, not technical proof of phishing or fraud. A single paid course advertisement can receive only the fee-based promotion point and remain Low risk. Pressure language, repeated actions or links, fees, and unverifiable outcome claims can combine to increase a score. These rules cannot determine whether a message was actually solicited, whether fees are fair, or whether a credential/provider claim is true; verify those independently. Repeated URLs are detected textually without opening them. Weights are defined in `content_heuristics.py` and can be overridden through `build_report(content_weights=...)`.

Malformed email structures and a missing or invalid `From` header produce explicit parsing warnings. MailSentry never invents a sender identity; SPF and DMARC remain unavailable/not evaluated when required data is missing.

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

Enable independent DKIM and DMARC checks for newly processed Gmail messages (DNS is queried with bounded timeouts; SPF still needs trusted SMTP inputs that Gmail API does not provide):

```powershell
python .\gmail_worker.py --once --verify-auth
```

The one-shot command prints a privacy-safe summary with discovered, queued, processed, failed, and retry counts plus the report directory. An empty first run saves the initial checkpoint and reports that future Inbox arrivals will be monitored; it does not scan older mail. Configuration and authorization failures exit nonzero with a setup hint. Unexpected internal errors are reported by type only, and the message remains resumable.

Choose a different interval in seconds, then stop with `Ctrl+C`:

```powershell
python .\gmail_worker.py --interval 120
```

On first start, the worker saves the current Gmail history checkpoint; it processes Inbox additions after that checkpoint rather than scanning old mail. It follows history pagination with bounded requests and resumes unfinished pages on later polls. If Gmail has expired the saved history, the worker resets to the current checkpoint instead of scanning the whole mailbox; changes during an extended outage may therefore be missed.

The worker creates and applies one of `MailSentry/Low`, `MailSentry/Medium`, or `MailSentry/High` using the same offline score thresholds. Labels are added only; Gmail's Spam classification and all other labels are left untouched.

### Privacy and operational notes

- Message content is fetched only for newly observed Inbox additions and held in memory for analysis. It is not written to SQLite or logs. With `--verify-auth`, MailSentry makes DNS TXT lookups for DKIM keys and DMARC policy only; it does not open message URLs or contact mail servers.
- SQLite stores the Gmail message ID, status, attempt count, sanitized error code, and sync checkpoint so work can be deduplicated and resumed. OAuth credentials and tokens remain local.
- Reports use a hashed message identifier for filenames and omit message body, sender/recipient addresses, raw URLs, attachment filenames, and raw finding evidence.
- Generated reports, local OAuth files, SQLite state, and Python caches are ignored by Git. Review report storage and access on your machine because even sanitized risk results are operationally sensitive.
- Gmail modify scope permits reading messages and changing labels. The worker uses it to read new Inbox messages and add only its risk labels.

Troubleshooting: confirm the Gmail API is enabled, `credentials.json` is a Desktop app client, the authorizing account is listed as an OAuth test user, and the browser consent grants Gmail modify access. For revoked authorization, stop the worker, remove local `token.json`, and restart to authorize again. A 401/403 stops the worker rather than retrying indefinitely; transient rate-limit/server errors use bounded retries and resume on a later poll.

## Authentication verification behavior and limits

- `--verify-auth` requires `spf3`, `dkimpy`, `dnspython`, and `checkdmarc`, installed by `python -m pip install -r requirements.txt`. These maintained libraries provide SPF evaluation, DKIM signature verification, bounded TXT resolution, and DMARC policy discovery/parsing.
- SPF supports PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR, and PERMERROR from the SPF engine. It runs only with a trusted SMTP context containing the actual client IP, MAIL FROM envelope sender, and HELO identity. No such context is available from a standalone `.eml` or Gmail API message, so MailSentry reports `NOT_EVALUATED` instead of guessing.
- DKIM distinguishes no signature (`NONE`), invalid signatures, missing public keys, temporary DNS errors, and verified signatures. Multiple signatures are checked up to a fixed limit. DKIM verification follows dkimpy's supported algorithms and message-format limitations.
- DMARC uses checkdmarc's applicable-policy lookup and parser, including organizational-domain policy discovery. PASS requires a valid DMARC policy and at least one passing aligned DKIM or SPF identity. A policy record by itself is never a pass or fail. When SPF is unavailable and no aligned DKIM signature passes, DMARC remains `NOT_EVALUATED` rather than inferring SPF failure.
- DNS queries use a 2-second per-query timeout; SPF has an 8-second total query budget and the DNS-backed library limits SPF mechanisms to the protocol's lookup limit. Offline or temporary DNS errors are reported without treating them as authentication failures. Normal unit tests mock these lookups and do not require live DNS.
- Authentication failures are indicators, not proof that a message is malicious. DMARC/SPF scoring uses only independent verification results. Untrusted `Authentication-Results` values remain visible as reported metadata and are not scored.

Run the full standard-library test suite (all DNS and library outcomes are mocked):

```powershell
python -m unittest discover -s tests -v
```

The suite includes a supplied sample regression, synthetic legitimate paid-training and promotional examples, malformed-header handling, and duplicate-link checks.
