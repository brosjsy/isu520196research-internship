"""Optional live OSINT integrations for OPRCF (standard library only).

These are the integrations that genuinely fit a first-person, consented
self-assessment. They use only urllib from the standard library, so there is
nothing to install.

  * Have I Been Pwned (account breach lookup) - requires YOUR OWN HIBP API key
    (their policy for the account endpoint). Set it in the HIBP_API_KEY
    environment variable. Used to auto-fill the OPRCF breach signal for your
    own email.

  * Pwned Passwords (k-anonymity) - free and key-less. Only the first five
    characters of the SHA-1 hash of the password ever leave your machine, so
    the password itself is never transmitted.

Use these ONLY against your own accounts/passwords or with explicit consent
(report Section 2.9). They query already-public breach corpora and add no new
collection capability.

CLI:
    python integrations.py --password            # prompts, key-less check
    HIBP_API_KEY=... python integrations.py --email you@example.com
"""

import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

USER_AGENT = "OPRCF-reference-implementation"
TIMEOUT = 10


class IntegrationError(RuntimeError):
    """Raised when a live lookup cannot be completed."""


# ---------------------------------------------------------------------
# Pwned Passwords (free, key-less, k-anonymity)
# ---------------------------------------------------------------------
def pwned_password_count(password: str) -> int:
    """Return how many times a password appears in breach corpora (0 = none).

    Privacy-preserving: only the first 5 hex chars of the SHA-1 hash are sent.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        "https://api.pwnedpasswords.com/range/%s" % prefix,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise IntegrationError("Pwned Passwords request failed: %s" % exc)
    for line in body.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix.strip().upper() == suffix:
            return int(count.strip() or 0)
    return 0


# ---------------------------------------------------------------------
# Have I Been Pwned account breaches (needs the user's own API key)
# ---------------------------------------------------------------------
def account_breaches(email: str,
                     api_key: Optional[str] = None) -> List[str]:
    """Return the list of breach names an email appears in ([] = none found).

    Requires a HIBP API key (argument or HIBP_API_KEY env var). Use only for
    your own email or with explicit consent.
    """
    api_key = api_key or os.environ.get("HIBP_API_KEY")
    if not api_key:
        raise IntegrationError(
            "No HIBP API key. Set HIBP_API_KEY (get one at "
            "https://haveibeenpwned.com/API/Key).")
    account = urllib.parse.quote(email.strip(), safe="")
    req = urllib.request.Request(
        "https://haveibeenpwned.com/api/v3/breachedaccount/%s"
        "?truncateResponse=true" % account,
        headers={"User-Agent": USER_AGENT, "hibp-api-key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return [item.get("Name", "?") for item in data]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []                      # 404 == no breach found (good news)
        if exc.code == 401:
            raise IntegrationError("HIBP API key rejected (401).")
        if exc.code == 429:
            raise IntegrationError("HIBP rate limit hit (429) - wait and retry.")
        raise IntegrationError("HIBP request failed: HTTP %s" % exc.code)
    except urllib.error.URLError as exc:
        raise IntegrationError("HIBP request failed: %s" % exc)


def breach_signal_for_email(email: str,
                            api_key: Optional[str] = None) -> Tuple[bool, List[str]]:
    """Convenience wrapper: (breach_hit, breach_names) for an email."""
    names = account_breaches(email, api_key)
    return (bool(names), names)


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def _main(argv=None) -> int:
    import argparse
    import getpass

    p = argparse.ArgumentParser(
        description="Optional OPRCF live breach lookups (first-person use only).")
    p.add_argument("--email", help="check this email against HIBP (needs key)")
    p.add_argument("--password", action="store_true",
                   help="check a password against Pwned Passwords (key-less)")
    args = p.parse_args(argv)

    if not args.email and not args.password:
        p.error("choose --email and/or --password")

    if args.password:
        pwd = getpass.getpass("Password (hidden, never transmitted in full): ")
        try:
            count = pwned_password_count(pwd)
        except IntegrationError as exc:
            print("error:", exc)
            return 1
        if count:
            print("BREACHED: seen %d times. Choose a different password." % count)
        else:
            print("Not found in Pwned Passwords corpora.")

    if args.email:
        try:
            hit, names = breach_signal_for_email(args.email)
        except IntegrationError as exc:
            print("error:", exc)
            return 1
        if hit:
            print("Breached in: %s" % ", ".join(names))
            print("-> set the OPRCF 'confirmed breach hit' signal.")
        else:
            print("No breaches found for that email.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
