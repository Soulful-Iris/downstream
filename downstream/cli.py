"""downstream - what does your email actually open?

    downstream --maildir ~/Library/Mail
    downstream --mbox ~/archive.mbox
    downstream --imap imap.fastmail.com --user you@example.com
    downstream --forget

Reads your own mailbox, locally and read-only, works out which services you have
accounts with, joins that against the public 2FA Directory, and writes one HTML
file. Nothing is uploaded. The only network call is for a public JSON file that
is never asked anything about you.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import webbrowser
from pathlib import Path

from . import chain, identify, page, policy, read

# Below this, the mailbox cannot support a claim. Refusing is the honest answer
# and it is the same discipline as a meter that will not print an unstable
# number: a thin mailbox produces a confident thin page, and a confident thin
# page is worse than being told to come back with more.
MIN_ACCOUNTS = 3


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="downstream", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group()
    src.add_argument("--maildir", help="a Maildir, or a folder containing several")
    src.add_argument("--mbox", help="an .mbox file")
    src.add_argument("--imap", metavar="HOST", help="IMAP server (read-only)")
    p.add_argument("--user", help="IMAP username, usually your address")
    p.add_argument("--folder", default="INBOX")
    p.add_argument("--port", type=int, default=993)
    p.add_argument("--me", metavar="ADDRESS_OR_DOMAIN",
                   help="your own address. Used only to decide whether a domain "
                        "registrar of yours controls the mail itself.")
    p.add_argument("--carrier", action="append", default=[], metavar="DOMAIN",
                   help="mark a domain as your mobile carrier (repeatable). The "
                        "built-in list is incomplete; see LIMITS in the README.")
    p.add_argument("--out", help="where to write the report")
    p.add_argument("--home", help="state directory (default ~/.downstream)")
    p.add_argument("--refresh", action="store_true", help="re-fetch the directory")
    p.add_argument("--open", action="store_true", help="open the report when done")
    p.add_argument("--forget", action="store_true",
                   help="delete everything this tool has written about you, and stop")
    a = p.parse_args(argv)

    home = Path(a.home).expanduser() if a.home else read.HOME
    os.environ.setdefault("DOWNSTREAM_HOME", str(home))

    if a.forget:
        gone = read.forget(home)
        for f in gone:
            print(f"  deleted {f}")
        print("  nothing of yours is left here." if gone else "  nothing to delete.")
        return 0

    if not (a.maildir or a.mbox or a.imap):
        p.print_help()
        return 2

    # --- read ---------------------------------------------------------------
    def tick(n, final=False):
        end = "\n" if final else "\r"
        print(f"  reading headers only - {n:,} messages, no bodies fetched",
              end=end, flush=True)

    if a.imap:
        user = a.user or input("  imap user: ")
        pw = os.environ.get("DOWNSTREAM_IMAP_PASSWORD") or getpass.getpass("  password: ")
        senders = read.from_imap(a.imap, user, pw, a.folder, a.port, progress=tick)
        me = a.me or user
    else:
        senders = read.from_local(a.maildir or a.mbox, progress=tick)
        me = a.me or ""

    messages = sum(s.count for s in senders.values())
    accts = identify.accounts(senders)
    print(f"  {len(senders):,} sender domains -> {len(accts)} look like accounts")

    if len(accts) < MIN_ACCOUNTS:
        print(f"\n  Only {len(accts)} account(s) found in {messages:,} messages.")
        print("  That is not enough to say anything useful, so I am not going to")
        print("  say it. Point this at a mailbox with more history, or a folder")
        print("  that includes archived mail rather than just the inbox.")
        return 3

    # --- join ---------------------------------------------------------------
    directory = policy.load(home / "2fa-all.json", refresh=a.refresh)
    if a.carrier:
        policy.CARRIER_DOMAINS.update(c.lower() for c in a.carrier)
    print(f"  joined against 2fa.directory ({len(directory):,} services, cached)")

    # --- walk ---------------------------------------------------------------
    domain = me.split("@")[-1].lower() if me else ""
    print("  walking the graph from your inbox...")
    g = chain.build(accts, directory, email_domain=domain)
    ms = chain.moves(g)

    # --- write --------------------------------------------------------------
    read.save(senders, home)
    out = Path(a.out).expanduser() if a.out else home / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(page.render(g, ms, {"messages": messages, "domains": len(senders)}))

    hit, one = len(g.reached()), len(g.at_depth(1))
    print(f"  wrote {out}")
    print(f"\n  {hit} of {len(g.nodes)} accounts are reachable from your inbox, "
          f"{one} of them in one hop.")
    if ms:
        covered = len({d for m in ms for d in m.covers})
        print(f"  {len(ms)} changes would disconnect {covered} of them. "
              f"The first is {ms[0].name}.")
    if a.open:
        webbrowser.open(out.as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
