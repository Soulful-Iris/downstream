"""Get the senders out of a mailbox, and only the senders.

Two sources, both of which keep the mailbox where it is:

  * a LOCAL EXPORT (Maildir or mbox) via `mailbox` from the stdlib. This is the
    documented default, because it needs no password at all.
  * IMAP via `imaplib`, also stdlib, with `select(readonly=True)` and
    `BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)]`.

`PEEK` and `readonly` together mean nothing is marked as read and nothing is
written back. Fetching only those three header fields means message bodies never
cross the wire in the first place - the privacy promise is a property of the
query, not of anybody's good intentions.

WHAT IS KEPT, and it is less than the PRD promised. The PRD said the output was
`(sender_domain, subject_class, first_seen, last_seen, count)`. Subjects are
never stored, not even the matched ones: each subject is classified as it goes
past and only the CLASS COUNTS survive. A stored subject line is stored content,
and "welcome to the clinic" is content whatever the tool's intentions were.
"""
from __future__ import annotations

import email.utils
import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .identify import classify_subject

HOME = Path(os.environ.get("DOWNSTREAM_HOME", Path.home() / ".downstream"))
SEEN = "senders.json"

_ADDR = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


@dataclass
class Sender:
    domain: str
    count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    classes: dict = field(default_factory=dict)   # subject class -> how many

    def note(self, subject: str, when: str) -> None:
        self.count += 1
        k = classify_subject(subject)
        if k:
            self.classes[k] = self.classes.get(k, 0) + 1
        if when:
            if not self.first_seen or when < self.first_seen:
                self.first_seen = when
            if not self.last_seen or when > self.last_seen:
                self.last_seen = when


def _domain_of(from_header: str) -> str:
    """The domain an email came from, lowercased. '' if it is not parseable."""
    if not from_header:
        return ""
    _, addr = email.utils.parseaddr(from_header)
    m = _ADDR.search(addr or from_header)
    return m.group(1).lower() if m else ""


def _when(date_header: str) -> str:
    """ISO date, or ''. Only the date - the time of day is nobody's business."""
    try:
        dt = email.utils.parsedate_to_datetime(date_header)
        return dt.date().isoformat() if dt else ""
    except (TypeError, ValueError):
        return ""


def _fold(records) -> dict[str, Sender]:
    out: dict[str, Sender] = {}
    for frm, subj, date in records:
        d = _domain_of(frm)
        if not d:
            continue
        out.setdefault(d, Sender(domain=d)).note(subj or "", _when(date or ""))
    return out


# --- local export ------------------------------------------------------------

def from_local(path: str | Path, progress=None) -> dict[str, Sender]:
    """Maildir or mbox on disk. Detected by looking, not by the extension."""
    import mailbox

    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"no mailbox at {p}")

    if p.is_dir():
        boxes = []
        # A Maildir has cur/new/tmp. A directory of them (Apple Mail, Thunderbird
        # profiles) has those nested somewhere below, so walk for them.
        if (p / "cur").is_dir():
            boxes.append(mailbox.Maildir(str(p), create=False))
        else:
            for sub in sorted(p.rglob("cur")):
                if sub.is_dir():
                    boxes.append(mailbox.Maildir(str(sub.parent), create=False))
            for mb in sorted(p.rglob("*.mbox")):
                if mb.is_file():
                    boxes.append(mailbox.mbox(str(mb), create=False))
        if not boxes:
            raise FileNotFoundError(
                f"{p} is a directory but no Maildir (cur/new/tmp) or .mbox inside it")
    else:
        boxes = [mailbox.mbox(str(p), create=False)]

    def records():
        n = 0
        for box in boxes:
            for key in box.iterkeys():
                try:
                    msg = box.get_message(key)
                except Exception:                                  # noqa: BLE001
                    continue                    # one unreadable message is not a failure
                n += 1
                if progress and n % 2000 == 0:
                    progress(n)
                yield msg.get("From", ""), msg.get("Subject", ""), msg.get("Date", "")
        if progress:
            progress(n, final=True)

    return _fold(records())


# --- IMAP --------------------------------------------------------------------

FETCH = "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])"
_HDR = re.compile(rb"^(From|Subject|Date):\s?(.*)$", re.I | re.M)


def from_imap(host: str, user: str, password: str, folder: str = "INBOX",
              port: int = 993, batch: int = 500, progress=None) -> dict[str, Sender]:
    """Read-only, headers only. Nothing is marked seen, nothing is written."""
    import imaplib

    conn = imaplib.IMAP4_SSL(host, port)
    try:
        conn.login(user, password)
        # readonly=True is not politeness: SELECT without it sets \Recent and can
        # mark messages seen on some servers. EXAMINE is what this becomes.
        typ, data = conn.select(folder, readonly=True)
        if typ != "OK":
            raise RuntimeError(f"cannot open {folder}: {data!r}")
        typ, data = conn.search(None, "ALL")
        if typ != "OK":
            raise RuntimeError(f"search failed: {data!r}")
        ids = data[0].split()

        def records():
            for i in range(0, len(ids), batch):
                chunk = b",".join(ids[i:i + batch])
                typ, resp = conn.fetch(chunk.decode(), FETCH)
                if typ != "OK":
                    continue
                for item in resp:
                    if not isinstance(item, tuple) or len(item) < 2:
                        continue
                    hdrs = {}
                    for m in _HDR.finditer(item[1]):
                        hdrs[m.group(1).decode().lower()] = _decode(m.group(2))
                    yield hdrs.get("from", ""), hdrs.get("subject", ""), hdrs.get("date", "")
                if progress:
                    progress(min(i + batch, len(ids)))
            if progress:
                progress(len(ids), final=True)

        return _fold(records())
    finally:
        try:
            conn.logout()
        except Exception:                                          # noqa: BLE001
            pass


def _decode(raw: bytes) -> str:
    from email.header import decode_header, make_header
    try:
        return str(make_header(decode_header(raw.decode("utf8", "replace"))))
    except Exception:                                              # noqa: BLE001
        return raw.decode("utf8", "replace")


# --- the only thing written to disk -----------------------------------------

def save(senders: dict[str, Sender], home: Path | None = None) -> Path:
    home = Path(home) if home else HOME
    home.mkdir(parents=True, exist_ok=True)
    f = home / SEEN
    # Create with 0600 BEFORE anything is written. Writing then chmod-ing leaves
    # a window where the file is world-readable, which is the whole point here.
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({d: asdict(s) for d, s in sorted(senders.items())}, fh, indent=1)
    return f


def load(home: Path | None = None) -> dict[str, Sender]:
    home = Path(home) if home else HOME
    f = home / SEEN
    if not f.exists():
        return {}
    return {d: Sender(**v) for d, v in json.loads(f.read_text()).items()}


def forget(home: Path | None = None) -> list[Path]:
    """Delete everything this tool has ever written about you. --forget."""
    home = Path(home) if home else HOME
    gone = []
    for name in (SEEN, "report.html"):
        f = home / name
        if f.exists():
            f.unlink()
            gone.append(f)
    return gone
