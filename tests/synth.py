"""Build a real Maildir with a planted answer.

Not a mock. `mailbox.Maildir` writes real files and `read.from_local` opens them
the same way it opens anybody's, so the test exercises the actual reader rather
than a stand-in for it. A test that constructs its own subject will pass whatever
you believe - that one is written down in my memory files and it cost a night.

Every service named here is a real entry in the 2FA Directory with the class it
really has, so the planted chain is a chain that exists in the world:

    inbox -> Vodafone [AU]  (no second factor at all)
          -> Ally Bank      (SMS only, so the carrier owns the code)
"""
from __future__ import annotations

import email.utils
import mailbox
import shutil
from pathlib import Path

# (domain, [(subject, how_many)]) - real domains, real classes.
PLANTED = [
    # --- accounts, with the mail that proves it ---
    ("vodafone.com.au", [("Your password reset request", 1),
                         ("Your monthly statement is ready", 6)]),
    ("ally.com",        [("New sign-in from a new device", 1),
                         ("Your statement is available", 9)]),
    ("adp.com",         [("Welcome to ADP - activate your account", 1),
                         ("Your payment confirmation", 4)]),
    ("gumroad.com",     [("Your receipt from Gumroad", 3)]),
    ("1password.com",   [("Verify your email address", 1)]),
    # TOTP-protected and money-holding. Not reachable by any CERTAIN path - the
    # only thing that touches it is Wren's conditional authbackup edge, which is
    # why it is here: an edge that fires in no fixture is untested code.
    ("youinvest.co.uk", [("Your statement is available", 3)]),
    ("aliexpress.com",  [("Your order confirmation", 2),
                         ("50% off flash sale ends tonight", 40)]),
    # --- not accounts: bulk mail that must not reach the page ---
    ("substack.com",    [("The weekly digest is here", 30)]),
    ("news.example.org", [("Newsletter: what we learned this month", 18)]),
    ("promo.retailer.example", [("Black Friday deal of the day", 25),
                                ("Don't miss 30% off", 12)]),
    ("mailing.list.example", [("New blog post: introducing our redesign", 9)]),
]

# Every account is on a security key. The ranker must come back short and dull.
BORING = [
    ("1password.com", [("Verify your email address", 1)]),
    ("adafruit.com",  [("Your receipt from Adafruit", 2)]),
    ("afternic.com",  [("Welcome to Afternic", 1)]),
    ("github.com",    [("New sign-in from a new device", 1)]),
]

# Nothing transactional at all. Should refuse rather than answer thinly.
EMPTY = [
    ("news.example.org", [("Newsletter: issue 12", 4)]),
]


def build(dest: Path, spec=PLANTED, me: str = "you@soulful-ai.dev") -> Path:
    """Write a Maildir at `dest` and return it. Overwrites."""
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    box = mailbox.Maildir(str(dest), create=True)
    n = 0
    for domain, subjects in spec:
        for subject, count in subjects:
            for i in range(count):
                n += 1
                msg = mailbox.MaildirMessage()
                msg["From"] = f"noreply@{domain}"
                msg["To"] = me
                msg["Subject"] = subject
                # Spread the dates so first_seen/last_seen mean something.
                msg["Date"] = email.utils.formatdate(1_756_000_000 + n * 3600)
                msg["Message-ID"] = f"<{n}@synth.invalid>"
                msg.set_payload(
                    "This body must never be read, stored or transmitted.\n"
                    "If it turns up anywhere in the output, something is wrong.\n")
                box.add(msg)
    box.flush()
    return dest


def expected_accounts(spec=PLANTED) -> set:
    """The domains a correct identifier would keep. Written by hand, on purpose.

    Derived from the SUBJECTS, not from the code that classifies them, so the
    test compares two independent things rather than one thing with itself.
    """
    if spec is PLANTED:
        return {"vodafone.com.au", "ally.com", "adp.com", "gumroad.com",
                "1password.com", "aliexpress.com", "youinvest.co.uk"}
    if spec is BORING:
        return {"1password.com", "adafruit.com", "afternic.com", "github.com"}
    if spec is HARD:
        # Hand-labelled by reading the subjects above, not by running the code.
        # someco.example is the judgement call: "Re: the invoice for last month"
        # is a human writing to you, not a service you hold an account with.
        return {"ally.com", "adp.com", "gumroad.com", "aliexpress.com",
                "1password.com"}
    return set()


# The cases that are genuinely ambiguous, written to try to break the classifier
# rather than to confirm it. 100% precision on a corpus I invented is not
# evidence; a corpus built to be hard is at least evidence of something.
#
# Each line is labelled with what a person would say, and `expected_accounts`
# below is that judgement, not the classifier's.
HARD = [
    # --- these ARE accounts, in ways that are easy to miss ---
    ("ally.com",         [("Password reset requested for your account", 1)]),
    ("adp.com",          [("Your payslip for August is available", 1),
                          ("Introducing your new ADP dashboard", 8)]),
    ("gumroad.com",      [("Your invoice #4471", 1),
                          ("Don't miss the summer sale", 15)]),
    ("aliexpress.com",   [("Your order has shipped", 1)]),
    ("1password.com",    [("New sign-in from a new device", 1)]),

    # --- these are NOT accounts, and they are shaped like ones ---
    # A mailing list double-opt-in. "Confirm your subscription" is one word away
    # from "confirm your account" and means something completely different.
    ("list.example.org", [("Confirm your subscription to our mailing list", 1),
                          ("Newsletter: issue 44", 12)]),
    # The single hardest one: a newsletter that says welcome.
    ("welcome.example",  [("Welcome to the weekly round-up", 1),
                          ("Weekly round-up: what we read", 20)]),
    # Marketing that borrows transactional language.
    ("shop.example",     [("Your cart is waiting for you", 6),
                          ("Last chance: 40% off everything", 9)]),
    # A person, not a service.
    ("someco.example",   [("Re: the invoice for last month", 3)]),
]
