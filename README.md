# MailSentry

MailSentry is a minimal, offline `.eml` analyzer for Python 3.10+. It uses only the standard library. It does not make network requests, open URLs, or execute attachments.

```console
python mailsentry.py samples/benign.eml
python mailsentry.py samples/suspicious.eml --json findings.json
python -m unittest discover -s tests
```

The terminal report explains each finding. JSON includes the source filename, findings and evidence, authentication results, score, risk level, and recommendations; it omits the message body and other headers.

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
