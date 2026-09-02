"""The three checks the PRD said this had to survive, and the ones that can go red.

    python3.12 tests/test_downstream.py

Every fixture is a real Maildir on disk read by the real reader, and every
service named is a real 2FA Directory entry with the class it really has. A test
that builds its own subject passes whatever you believe.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import synth                                                        # noqa: E402
from downstream import chain, identify, page, policy, read          # noqa: E402

DIR = policy.load()


def _run(spec, email_domain="soulful-ai.dev"):
    d = Path(tempfile.mkdtemp()) / "mb"
    synth.build(d, spec)
    senders = read.from_local(d)
    accts = identify.accounts(senders)
    g = chain.build(accts, DIR, email_domain=email_domain)
    shutil.rmtree(d.parent, ignore_errors=True)
    return senders, accts, g


# --- 1. the planted chain ----------------------------------------------------

def test_the_planted_sim_swap_chain_is_found():
    """inbox -> Vodafone [AU] (no 2FA) -> Ally Bank (SMS only). Two hops.

    This is the claim the whole project rests on: that a graph finds something a
    list cannot. If this goes red, chain.py is decoration.
    """
    _, _, g = _run(synth.PLANTED)
    bank = g.nodes["ally.com"]
    assert bank.reachable, "the bank was not reached at all"
    assert bank.depth == 2, f"expected 2 hops, got {bank.depth}"
    kinds = [e.kind for e in bank.path]
    assert kinds == [chain.RESET, chain.SIM], f"wrong path shape: {kinds}"
    assert bank.path[0].dst == "vodafone.com.au", "did not go via the carrier"
    assert bank.path[1].src == "vodafone.com.au"


def test_one_hop_accounts_are_at_depth_one():
    _, _, g = _run(synth.PLANTED)
    for d in ("adp.com", "gumroad.com", "vodafone.com.au", "aliexpress.com"):
        assert g.nodes[d].depth == 1, f"{d} should be one hop, is {g.nodes[d].depth}"


def test_the_carrier_conditionally_reaches_app_protected_accounts():
    """Wren's finding: the SIM edge does not stop at PHONE.

    Some authenticators register a new device against the phone number, so
    "this service offers an authenticator app" can be true and irrelevant. The
    path must exist, must be CONDITIONAL, and must be drawn as needing an
    assumption - leaving it out silently tells somebody their app-protected
    accounts survive a SIM swap. NOTE: the wording on the page was corrected after
    checking - Authy multi-device is off by default since 2022, and Google and
    Microsoft authenticators restore from a cloud account, not a phone number.
    """
    _, _, g = _run(synth.PLANTED)
    n = g.nodes["youinvest.co.uk"]
    assert n.klass == policy.APP, "fixture drifted; this should be a TOTP service"
    assert n.reachable, "an APP account behind a reachable carrier was called safe"
    assert n.only_conditional, "this path must be conditional, not asserted"
    assert n.path[-1].kind == chain.AUTHBACKUP
    assert n.path[-1].src == "vodafone.com.au"
    assert not n.path[-1].certain


def test_the_conditional_path_is_visibly_conditional_on_the_page():
    _, _, g = _run(synth.PLANTED)
    out = page.render(g, chain.moves(g), {"messages": 1, "domains": 1})
    assert "cond" in out, "conditional rows are not marked"
    assert "needs the stated assumption" in out


def test_a_hardware_account_is_not_reachable():
    _, _, g = _run(synth.PLANTED)
    assert not g.nodes["1password.com"].reachable, \
        "an account with a security key was reported as reachable from email"


# --- 2. the negative control, which is the one that matters ------------------

def test_a_mailbox_of_hardware_keys_comes_back_empty():
    """A ranker that alarms everybody is not a ranker.

    Five instruments in my memory files could only produce the answer I was
    already imagining. This is the case where the honest answer is 'you are
    fine', and if the tool cannot say that it says nothing.
    """
    _, accts, g = _run(synth.BORING, email_domain="gmail.com")
    assert len(accts) == 4, f"identification changed: {sorted(accts)}"
    assert g.reached() == [], \
        f"claimed {len(g.reached())} reachable in a mailbox that is all security keys"
    assert chain.moves(g) == [], "invented moves with nothing to fix"


def test_the_headline_says_so_when_nothing_is_reachable():
    _, _, g = _run(synth.BORING, email_domain="gmail.com")
    out = page.render(g, chain.moves(g), {"messages": 5, "domains": 4})
    assert "None of your 4 accounts" in out
    assert "the good answer" in out


# --- 3. identification, measured rather than assumed -------------------------

def test_identification_precision_and_recall_on_the_planted_set():
    """Hand-labelled in synth.expected_accounts, derived from the SUBJECTS.

    The expected set is written by reading the fixture's subject lines, not by
    running the classifier, so this compares two independent things.
    """
    _, accts, _ = _run(synth.PLANTED)
    got, want = set(accts), synth.expected_accounts(synth.PLANTED)
    tp = len(got & want)
    fp = sorted(got - want)
    fn = sorted(want - got)
    precision = tp / len(got) if got else 0.0
    recall = tp / len(want)
    print(f"      precision {precision:.0%}  recall {recall:.0%}"
          f"  false positives {fp}  missed {fn}")
    # The PRD's own kill condition: below ~90% precision the page is noise.
    assert precision >= 0.90, f"precision {precision:.0%} - the page would be noise"
    assert not fp, f"newsletters counted as accounts: {fp}"
    assert recall >= 0.90, f"recall {recall:.0%}, missed {fn}"


def test_identification_on_the_adversarial_set():
    """The corpus built to break it, not to confirm it.

    100% on a fixture I invented is not evidence. This one was written to fail
    and it did - 80% precision, below the PRD's own kill line - and it found two
    real defects: "Your payslip for August" matched nothing (losing a PAYROLL
    account, the worst possible miss), and "Re: the invoice for last month" put
    a colleague on the page as a service.

    Be honest about what this number is worth: the rules were adjusted AFTER
    seeing these cases, so this is a corpus I have now fitted. It is 19
    hand-labelled senders, not a real mailbox. The README says so.
    """
    _, accts, _ = _run(synth.HARD)
    got, want = set(accts), synth.expected_accounts(synth.HARD)
    fp, fn = sorted(got - want), sorted(want - got)
    precision = len(got & want) / len(got) if got else 0.0
    print(f"      hard set: precision {precision:.0%}  fp {fp}  missed {fn}")
    assert not fp, f"shaped-like-an-account bulk mail got through: {fp}"
    assert not fn, f"real accounts missed: {fn}"


def test_a_reply_is_a_person_not_a_service():
    from downstream.identify import classify_subject
    assert classify_subject("Your invoice #4471") == "txn"
    assert classify_subject("Re: the invoice for last month") is None
    assert classify_subject("Fwd: your receipt") is None


def test_a_payslip_is_a_transaction():
    from downstream.identify import classify_subject
    assert classify_subject("Your payslip for August is available") == "txn"


def test_bulk_senders_are_never_accounts():
    senders, accts, _ = _run(synth.PLANTED)
    for d in ("substack.com", "news.example.org", "promo.retailer.example",
              "mailing.list.example"):
        assert d in senders, f"fixture broken: {d} not read at all"
        assert d not in accts, f"{d} is a mailing list and was counted as an account"


def test_a_receipt_beats_a_wall_of_marketing():
    """AliExpress: 2 order confirmations, 40 adverts. It is still an account.

    The first version of is_account() had a flat 10:1 bulk veto and threw this
    away. The fixture caught it. Somebody who ordered twice has an account
    however much marketing arrives alongside.
    """
    _, accts, _ = _run(synth.PLANTED)
    assert "aliexpress.com" in accts
    assert accts["aliexpress.com"].classes["against"] == 40


# --- 4. the pessimistic default ----------------------------------------------

def test_an_unknown_service_is_treated_as_open():
    klass, svc = policy.classify("some-service-nobody-has-heard-of.invalid", DIR)
    assert svc is None
    assert klass == policy.UNKNOWN
    assert policy.SEVERITY[policy.UNKNOWN] == policy.SEVERITY[policy.OPEN], \
        "an unknown lock must be scored as no lock"


def test_email_as_a_second_factor_is_not_a_second_factor():
    klass, svc = policy.classify("gumroad.com", DIR)
    assert svc.methods == frozenset({"email"})
    assert klass == policy.THEATRE, "email-only 2FA must not count as protection"


def test_subdomains_resolve_to_the_parent_service():
    _, svc = policy.classify("mail.notifications.adp.com", DIR)
    assert svc is not None and svc.domain == "adp.com"


# --- 5. the moves ------------------------------------------------------------

def test_the_carrier_outranks_the_bank_in_the_moves():
    """The whole point of a set-cover: fix the node others run through.

    A severity sort would put the bank first because a bank is frightening. The
    carrier is the answer, and nobody would guess it.
    """
    _, _, g = _run(synth.PLANTED)
    ms = chain.moves(g)
    assert ms, "no moves produced"
    assert ms[0].domain == "vodafone.com.au", \
        f"first move should be the carrier, was {ms[0].domain}"
    # It covers itself, the SMS-protected bank, and - since Wren's finding - the
    # TOTP account whose codes can restore over SMS. Adding that edge made the
    # carrier MORE important, which is his argument in one number.
    assert {"vodafone.com.au", "ally.com"} <= set(ms[0].covers)
    assert "youinvest.co.uk" in ms[0].covers, \
        "the conditional authbackup reach is not counted in the set-cover"
    assert len(ms[0].covers) > max(len(m.covers) for m in ms[1:]), \
        "the carrier must cover strictly more than any single leaf"


def test_moves_never_claim_to_cover_something_still_reachable():
    _, _, g = _run(synth.PLANTED)
    ms = chain.moves(g)
    blocked = {m.domain for m in ms}
    still = chain._reachable_without(g, blocked)
    claimed = {d for m in ms for d in m.covers}
    assert not (claimed & still), \
        f"claimed to remove {sorted(claimed & still)} but they are still reachable"


# --- 6. privacy is a property of the code, not of the intentions -------------

def test_nothing_but_domains_dates_and_counts_is_ever_written():
    home = Path(tempfile.mkdtemp())
    senders, _, _ = _run(synth.PLANTED)
    f = read.save(senders, home)
    blob = f.read_text()
    for leak in ("flash sale", "Black Friday", "password reset request",
                 "Your receipt", "noreply@", "This body must never"):
        assert leak.lower() not in blob.lower(), f"{leak!r} was written to disk"
    assert oct(f.stat().st_mode)[-3:] == "600", "state file is not 0600"
    shutil.rmtree(home, ignore_errors=True)


def test_forget_removes_everything():
    home = Path(tempfile.mkdtemp())
    senders, _, _ = _run(synth.PLANTED)
    read.save(senders, home)
    (home / "report.html").write_text("x")
    gone = read.forget(home)
    assert len(gone) == 2
    assert not list(home.glob("senders.json"))
    assert not list(home.glob("report.html"))
    shutil.rmtree(home, ignore_errors=True)


# --- 7. the refusal path -----------------------------------------------------

def test_a_thin_mailbox_is_refused_rather_than_answered():
    from downstream import cli
    d = Path(tempfile.mkdtemp())
    synth.build(d / "mb", synth.EMPTY)
    rc = cli.main(["--maildir", str(d / "mb"), "--home", str(d / "home"),
                   "--out", str(d / "r.html")])
    assert rc == 3, f"expected the refusal exit code, got {rc}"
    assert not (d / "r.html").exists(), "wrote a report it had no business writing"
    shutil.rmtree(d, ignore_errors=True)


# --- 8. the page ------------------------------------------------------------

def test_the_page_says_offered_not_switched_on():
    _, _, g = _run(synth.PLANTED)
    out = page.render(g, chain.moves(g), {"messages": 162, "domains": 10})
    assert "offers</b>, not what you have" in out, \
        "the page must say every time that this is what is OFFERED"


def test_the_page_is_self_contained():
    """A page about not leaking must not fetch anything when it is opened."""
    _, _, g = _run(synth.PLANTED)
    out = page.render(g, chain.moves(g), {"messages": 1, "domains": 1})
    for bad in ("http://", "src=", "<script", "@import", "fonts.googleapis"):
        assert bad not in out, f"the report reaches out to {bad!r}"
    assert "https://" not in out.replace(
        "https://github.com/Soulful-Iris/downstream", ""), "external https reference"


def test_the_report_renders_only_ascii():
    """Rendered on somebody else's machine with somebody else's fonts.

    Three nights running I have shipped a glyph this box has no font for. An
    arrow I cannot verify is an arrow I should not use.
    """
    _, _, g = _run(synth.PLANTED)
    out = page.render(g, chain.moves(g), {"messages": 1, "domains": 1})
    bad = sorted({c for c in out if ord(c) > 127})
    assert not bad, f"non-ascii in the report: {[hex(ord(c)) for c in bad]}"


if __name__ == "__main__":
    import traceback
    fails = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"  ok   {name}")
        except Exception:
            fails += 1
            print(f"  FAIL {name}")
            traceback.print_exc()
    print("all green" if not fails else f"{fails} failed")
    sys.exit(1 if fails else 0)
