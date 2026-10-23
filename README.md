# MailSentry

MailSentry is a minimal, offline `.eml` analyzer for Python 3.10+. It uses only the standard library and reads plain-text bodies, falling back to HTML when no plain-text part exists. You must provide an `.eml` file; live inbox integration is not implemented. MailSentry does not make network requests, open URLs, or execute attachments.

In Windows PowerShell, run a sample:

```powershell
python .\mailsentry.py .\samples\suspicious.eml
```

Generate both privacy-safe JSON and a readable Markdown report in one run:

```powershell
python .\mailsentry.py .\samples\suspicious.eml --json .\reports\suspicious-report.json --report .\reports\suspicious-report.md
```

Run the tests:

```powershell
python -m unittest discover -s tests
```

The terminal and Markdown reports explain each finding and recommended actions. The score is a heuristic, not a probability of compromise. Missing authentication results are shown as unavailable, not failed. Both report formats omit the message body, headers, and raw finding evidence such as addresses, URLs, and attachment names; the Markdown report includes only the input filename. JSON includes rule explanations, authentication results, score, risk level, and recommendations.

## Rules and scoring

Each rule contributes at most once to a message, regardless of repeated instances. Findings are:

| Rule | Points |
| --- | ---: |
| Reply-To differs from From | +2 |
| URL host is a raw IPv4 or IPv6 address | +2 |
| Attachment has a risky extension (`.bat`, `.cmd`, `.com`, `.exe`, `.iso`, `.jar`, `.js`, `.jse`, `.lnk`, `.msi`, `.ps1`, `.scr`, `.vbe`, `.vbs`) | +3 |
| DMARC result is `fail` | +2 |
| SPF result is `fail` | +1 |

Risk levels: Low = 0–1, Medium = 2–3, High = 4+. SPF, DKIM, and DMARC are read from `Authentication-Results`; absent results are reported as `unavailable`, not as failures. DKIM is reported but does not add points.
