"""Small, offline .eml analyzer for MailSentry."""

from __future__ import annotations

import argparse
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


def parse_eml(path: str | Path) -> dict[str, Any]:
    """Parse an RFC 5322 message without following links or opening attachments."""
    source = Path(path)
    with source.open("rb") as message_file:
        message = BytesParser(policy=policy.default).parse(message_file)

    bodies: list[str] = []
    attachments: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
        elif part.get_content_type() == "text/plain":
            try:
                content = part.get_content()
            except (LookupError, UnicodeDecodeError):
                content = ""
            if isinstance(content, str):
                bodies.append(content)

    return {
        "source": source.name,
        "headers": {name.lower(): str(value) for name, value in message.items()},
        "body": "\n".join(bodies),
        "attachments": attachments,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze an email message offline.")
    parser.add_argument("eml", help="Path to a .eml file")
    parser.add_argument("--json", dest="json_path", help="Write parsed data as JSON")
    args = parser.parse_args()
    result = parse_eml(args.eml)
    print(json.dumps(result, indent=2))
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
