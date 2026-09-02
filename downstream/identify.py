"""Which of the senders in a mailbox are actually ACCOUNTS.

A sender domain is not an account. Most of a mailbox is newsletters, marketing
and one-off receipts from places you have never registered with, and counting
those would turn the report into a pile of noise where the ranking means
nothing.

The signal that separates them is the transactional subject line, and the
strongest one is a **password reset**: a service only sends that to an address it
holds an account for. A sign-in alert and a verification code are the same kind
of evidence. Those three are treated as proof.

Everything here is deliberately conservative. A false positive puts a service on
the page that the person does not use, which makes the whole page less
believable; a false negative just leaves something out, and the report says in
words that it can only see what has emailed you.

ENGLISH ONLY, and that is a real limit rather than an oversight - it is in the
README. A German or Spanish mailbox will under-report, which fails in the
direction of saying too little.
"""
from __future__ import annotations

import re

# --- proof: only sent to an address that HAS an account ----------------------
PROOF = [
    r"\bpassword reset\b", r"\breset your password\b", r"\bforgot(ten)? password\b",
    r"\bchange your password\b", r"\bpassword (has been |was )?changed\b",
    r"\bnew (sign[- ]?in|login)\b", r"\bsign[- ]?in (alert|attempt|from)\b",
    r"\bnew device\b", r"\bunusual (activity|sign[- ]?in)\b",
    r"\b(verification|security|one[- ]time|login) code\b",
    r"\byour code is\b", r"\bis your .{0,20}code\b",
    r"\btwo[- ]factor\b", r"\b2fa\b", r"\bauthenticat(e|ion) (code|request)\b",
    r"\bverify your (email|account|identity|address)\b",
    r"\bconfirm your (email|account|address)\b",
    r"\bemail (address )?(verification|confirmed)\b",
]

# --- a transaction happened. You bought, paid, booked or hold a balance. ------
#
# Split out of the old single STRONG tier because the fixture caught the rule
# being wrong: AliExpress in the planted mailbox sends 2 order confirmations and
# 40 adverts, and a flat 10:1 bulk veto threw the account away. Somebody who
# ordered twice has an account, however much marketing arrives alongside it.
#
# A marketing list sends "welcome to our newsletter". It does not send "your
# order confirmation". So a transaction is evidence at proof strength and is
# never overruled by volume, and only the SIGNUP tier below is.
TXN = [
    r"\byour (receipt|invoice|order|payment|booking|reservation|refund)\b",
    r"\border (#|number|confirmation|confirmed|shipped|has shipped)\b",
    r"\bpayment (received|confirmation|successful|failed|declined|due)\b",
    r"\bpurchase confirmation\b", r"\bwe('| ha)ve received your order\b",
    r"\bthanks? for your (order|purchase|payment)\b",
    r"\byour (subscription|membership|plan) (has|will|is|renew)\w*\b",
    r"\b(monthly|annual|your) statement\b",
    r"\baccount (statement|summary|balance)\b",
    r"\binvoice (#|number|attached|for)\b",
    # Found by the adversarial fixture: "Your payslip for August is available"
    # matched nothing, and losing a payroll account is the worst possible miss.
    r"\b(payslip|pay stub|paystub|payroll|remittance advice)\b",
    r"\byour (policy|premium|benefits?) (document|statement|renewal)\b",
]

# --- signup-shaped: usually an account, but a newsletter says this too --------
SIGNUP = [
    r"\bwelcome to\b", r"\baccount (has been )?created\b", r"\bactivate your account\b",
    r"\bthanks? for (signing up|registering|joining|creating|subscribing)\b",
    r"\byour (subscription|membership|plan)\b",
    r"\bterms (of service|and conditions) (have )?(are )?chang\w+\b",
    r"\bprivacy policy (update|has changed)\b",
]

# --- against: the shape of bulk mail nobody has an account for ---------------
AGAINST = [
    r"\bnewsletter\b", r"\bdigest\b", r"\bweekly (round[- ]?up|recap|update)\b",
    r"\b\d{1,3}% off\b", r"\bsale (ends|starts|now)\b", r"\bflash sale\b",
    r"\bblack friday\b", r"\bcyber monday\b", r"\bdeal of the\b",
    r"\blast chance\b", r"\bdon'?t miss\b", r"\blimited time\b",
    r"\bwebinar\b", r"\bjoin us\b", r"\bnew (blog )?post\b",
    r"\bunsubscribe\b", r"\byou (might|may) (also )?like\b",
    r"\bintroducing\b", r"\bnow available\b",
]

PROOF_RE = re.compile("|".join(PROOF), re.I)
TXN_RE = re.compile("|".join(TXN), re.I)
SIGNUP_RE = re.compile("|".join(SIGNUP), re.I)
AGAINST_RE = re.compile("|".join(AGAINST), re.I)

# Sender-side hints. A domain that only ever sends from `news@` or `marketing@`
# is a broadcaster; `noreply@` says nothing either way and is not used.
BULK_LOCALPARTS = {"news", "newsletter", "marketing", "promo", "promotions",
                   "offers", "deals", "campaign", "mailing", "list"}


REPLY = re.compile(r"^\s*(re|fwd?|aw|antw|rv)\s*:", re.I)


def classify_subject(subject: str) -> str | None:
    """'proof' | 'txn' | 'signup' | 'against' | None. Order matters.

    A single subject can be both - "Your receipt from the 50% off sale" - and
    the transactional half is the informative one, so the account-shaped tiers
    are tested before the marketing one.
    """
    if not subject:
        return None
    # A service does not reply to you. "Re: the invoice for last month" is a
    # person in a thread, and it was the only false positive in the adversarial
    # fixture - it matched "invoice for" and put a colleague on the page as a
    # service. A reply is conversation and carries no evidence either way.
    if REPLY.match(subject):
        return None
    if PROOF_RE.search(subject):
        return "proof"
    if TXN_RE.search(subject):
        return "txn"
    if SIGNUP_RE.search(subject):
        return "signup"
    if AGAINST_RE.search(subject):
        return "against"
    return None


def is_account(sender, bulk_ratio: int = 10) -> tuple[bool, str]:
    """(verdict, why). `sender` is a read.Sender.

    The rule, and it is deliberately dull:

      * any `proof` subject   -> yes. A reset mail is not sent to strangers.
      * any `txn` subject     -> yes. You paid somebody. Volume of marketing
                                 alongside it is irrelevant, which is the bit
                                 the planted mailbox corrected.
      * `signup` subjects     -> yes, UNLESS the domain is overwhelmingly bulk.
                                 "Welcome to" is the one phrase a newsletter and
                                 a real account both say.
      * nothing but `against` -> no.
      * nothing at all        -> no. Silence is not evidence of an account, and
                                 this is the one place in the tool where an
                                 absence means "no", because the cost of
                                 guessing wrong is a page full of noise.
    """
    c = sender.classes or {}
    proof = c.get("proof", 0)
    txn = c.get("txn", 0)
    signup = c.get("signup", 0)
    against = c.get("against", 0)

    if proof:
        return True, f"{proof} password-reset / sign-in / verification mail(s)"
    if txn:
        return True, f"{txn} receipt / payment / statement mail(s)"
    if signup:
        if against and against > signup * bulk_ratio:
            return False, (f"only signup-shaped mail, and mostly bulk "
                           f"({against} promotional, {signup} signup)")
        return True, f"{signup} signup or account-change mail(s)"
    if against:
        return False, f"{against} promotional mail(s), nothing transactional"
    return False, "nothing that looks like an account mail"


def accounts(senders: dict) -> dict:
    """Filter a {domain: Sender} map down to the ones that look like accounts."""
    out = {}
    for d, s in senders.items():
        ok, why = is_account(s)
        if ok:
            s.why = why
            out[d] = s
    return out
