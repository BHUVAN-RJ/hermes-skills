"""CLI: python -m injection_scanner --json < email.json  |  --subject S --body B

Prints the scan result as JSON. Exits 0 for every scanned email (flagged or
not); the verdict is the "flagged" field. Exits 2 only on unusable input.
"""

from __future__ import annotations

import argparse
import json
import sys

from .models import DEFAULT_THRESHOLD
from .scanner import scan_email
from .wrap import wrap_untrusted


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="injection_scanner", description="Score an email for prompt-injection risk.")
    parser.add_argument("--json", action="store_true", help="read {subject, body, sender, html} JSON from stdin")
    parser.add_argument("--subject", default="", help="email subject")
    parser.add_argument("--body", default="", help="email plain-text body")
    parser.add_argument("--sender", default="", help="email sender")
    parser.add_argument("--html-file", default=None, help="path to the email's HTML part")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="flag at or above this score")
    parser.add_argument("--wrap", action="store_true", help="also include the wrapped <untrusted_email> text")
    return parser


def read_email_fields(arguments: argparse.Namespace) -> dict:
    if arguments.json:
        stdin_text = sys.stdin.read()
        email_fields = json.loads(stdin_text)
        if not isinstance(email_fields, dict):
            raise ValueError("JSON input must be an object with subject/body fields")
        return email_fields
    email_fields = {"subject": arguments.subject, "body": arguments.body, "sender": arguments.sender}
    if arguments.html_file:
        with open(arguments.html_file, encoding="utf-8") as html_file:
            email_fields["html"] = html_file.read()
    return email_fields


def main(argv: list[str] | None = None) -> int:
    arguments = build_argument_parser().parse_args(argv)
    try:
        email_fields = read_email_fields(arguments)
    except (ValueError, OSError) as input_error:
        error_output = {"error": str(input_error)}
        print(json.dumps(error_output), file=sys.stderr)
        return 2
    subject = str(email_fields.get("subject") or "")
    body = str(email_fields.get("body") or "")
    sender = str(email_fields.get("sender") or "")
    html = email_fields.get("html")
    scan_result = scan_email(subject, body, sender=sender, html=html, threshold=arguments.threshold)
    output = scan_result.to_dict()
    if arguments.wrap:
        output["wrapped"] = wrap_untrusted(scan_result, subject, body)
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
