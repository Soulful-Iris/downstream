"""What it takes to get into a service, joined from the public 2FA Directory.

The directory (https://2fa.directory, MIT) records which second factors a
service OFFERS. That is not the same as what you have switched on, and the
report says so at the top of every page. This is a map of your best possible
defence; the real one is at best this good.

The one rule that matters here: **UNKNOWN is scored as OPEN.** A service that is
not in the directory tells us nothing, and absence of evidence must not downgrade
a risk. Every expensive failure in my record is a check that read as fine because
it had nothing to say.
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DIRECTORY_URL = "https://api.2fa.directory/v3/all.json"
CACHE = Path(os.environ.get("DOWNSTREAM_HOME", Path.home() / ".downstream"))

# --- the classes, worst first ------------------------------------------------
OPEN = "OPEN"          # no second factor exists. The inbox is the whole lock.
THEATRE = "THEATRE"    # the only second factor offered is email.
PHONE = "PHONE"        # SMS or call only. Survives an inbox, not a SIM swap.
APP = "APP"            # TOTP available.
HARDWARE = "HARDWARE"  # U2F or a security key available.
UNKNOWN = "UNKNOWN"    # not in the directory -> treated as OPEN.

# How bad, for sorting. Lower is worse.
SEVERITY = {OPEN: 0, UNKNOWN: 0, THEATRE: 1, PHONE: 2, APP: 3, HARDWARE: 4}

EXPLAIN = {
    OPEN: "no second factor exists at all - your inbox is the whole lock",
    THEATRE: "the only second factor offered is an emailed code, which is not a "
             "second factor when the attacker is reading the email",
    PHONE: "SMS or a phone call only - survives a stolen inbox, does not survive "
           "a SIM swap",
    APP: "an authenticator app is available",
    HARDWARE: "a security key is available",
    UNKNOWN: "not in the directory, so nothing is known - counted as the bad case",
}

STRONG = {"totp", "u2f", "custom-hardware", "custom-software"}

# Categories that mean money can move. Used for ranking, not for the graph.
MONEY = {"banking", "finance", "investing", "cryptocurrencies", "payments", "retail"}

# Categories whose accounts are themselves KEYS to other accounts.
REGISTRAR = {"domains"}
MAILHOST = {"email"}
IDENTITY = {"identity"}          # password managers / SSO live here

# The directory has no `telecom` keyword. The PRD assumed one and was wrong.
#
# Carriers are filed under `utilities`, but so are electricity companies and
# broadband providers, and saying "your power company can SIM-swap you" would be
# exactly the confidently-wrong output this tool exists to avoid. So the carrier
# edge fires only on an explicit list.
#
# This list is MINE, it is curated, and it is incomplete - which is why it is in
# the README's LIMITS and why `--carrier DOMAIN` exists to add to it. It is
# deliberately small and only holds mobile operators, because the edge it creates
# (owning this gets you every SMS second factor) is only true of mobile.
CARRIER_DOMAINS = {
    "att.com", "verizon.com", "verizonwireless.com", "t-mobile.com", "sprint.com",
    "uscellular.com", "mintmobile.com", "visible.com", "cricketwireless.com",
    "boostmobile.com", "metrobyt-mobile.com", "googlefi.com", "fi.google.com",
    "vodafone.com", "vodafone.co.uk", "vodafone.de", "o2.co.uk", "ee.co.uk",
    "three.co.uk", "giffgaff.com", "tescomobile.com", "virginmedia.com",
    "telekom.de", "telekom.com", "orange.fr", "orange.com", "sfr.fr", "free.fr",
    "movistar.es", "vodafone.es", "yoigo.com",
    "rogers.com", "bell.ca", "telus.com", "fido.ca", "koodomobile.com",
    "freedommobile.ca", "publicmobile.ca",
    "telstra.com.au", "optus.com.au", "vodafone.com.au", "amaysim.com.au",
    "docomo.ne.jp", "au.com", "softbank.jp", "rakuten.co.jp",
    "claro.com", "movistar.com", "tim.it", "wind.it", "vivo.com.br",
}


@dataclass
class Service:
    """One entry from the directory, reduced to what this tool needs."""
    name: str
    domain: str
    methods: frozenset
    keywords: frozenset
    documentation: str = ""

    @property
    def klass(self) -> str:
        m = self.methods
        if not m:
            return OPEN
        if m & STRONG:
            return HARDWARE if (m & {"u2f", "custom-hardware"}) else APP
        if m & {"sms", "call"}:
            return PHONE
        if m == {"email"} or m <= {"email"}:
            return THEATRE
        return PHONE

    @property
    def holds_money(self) -> bool:
        return bool(self.keywords & MONEY)

    @property
    def is_registrar(self) -> bool:
        return bool(self.keywords & REGISTRAR)

    @property
    def is_mailhost(self) -> bool:
        return bool(self.keywords & MAILHOST)

    @property
    def is_identity(self) -> bool:
        return bool(self.keywords & IDENTITY)

    @property
    def is_carrier(self) -> bool:
        return self.domain.lower() in CARRIER_DOMAINS


class Directory:
    """Every domain the directory knows, resolvable by exact or parent domain."""

    def __init__(self, entries: list[Service], extra_carriers: set | None = None):
        self.entries = entries
        self.by_domain: dict[str, Service] = {}
        for s in entries:
            for d in {s.domain, *getattr(s, "_extra_domains", ())}:
                if d:
                    self.by_domain.setdefault(d.lower(), s)
        if extra_carriers:
            CARRIER_DOMAINS.update(d.lower() for d in extra_carriers)

    def __len__(self) -> int:
        return len(self.entries)

    def lookup(self, domain: str) -> Service | None:
        """Exact match, then walk up the labels: mail.foo.co.uk -> foo.co.uk.

        Walking up rather than parsing a public-suffix list keeps this
        dependency-free. It can over-match on a shared suffix, which is why the
        walk stops at two labels and never returns a bare TLD.
        """
        d = (domain or "").lower().strip(".")
        if not d:
            return None
        if d in self.by_domain:
            return self.by_domain[d]
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.by_domain:
                return self.by_domain[parent]
        return None


def load(path: Path | None = None, refresh: bool = False) -> Directory:
    """Read the cached directory, fetching it once if it is not there.

    This is the ONLY network call the whole tool makes, it is a public JSON file,
    and it carries nothing about the person running it.
    """
    cache = Path(path) if path else CACHE / "2fa-all.json"
    if refresh or not cache.exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        # urllib's default User-Agent gets a 403 here where curl does not. Found
        # on the first end-to-end run, which is the path EVERY new user takes -
        # without this the tool works perfectly for me and for nobody else,
        # because I had the file cached from writing the plan.
        req = urllib.request.Request(DIRECTORY_URL, headers={
            "User-Agent": "downstream/0.1 (+https://github.com/Soulful-Iris/downstream)",
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
        except Exception as e:                                     # noqa: BLE001
            raise RuntimeError(
                f"could not fetch the 2FA Directory ({e}).\n"
                f"    It is a public file. Download it by hand if you prefer:\n"
                f"      curl -o {cache} {DIRECTORY_URL}") from e
        json.loads(data)          # refuse to cache something that is not the data
        cache.write_bytes(data)
        cache.chmod(0o600)
    raw = json.loads(cache.read_text())
    out = []
    for name, meta in raw:
        s = Service(
            name=name,
            domain=(meta.get("domain") or "").lower(),
            methods=frozenset(meta.get("tfa") or []),
            keywords=frozenset(meta.get("keywords") or []),
            documentation=meta.get("documentation") or "",
        )
        s._extra_domains = tuple(d.lower() for d in (meta.get("additional-domains") or []))
        out.append(s)
    return Directory(out)


def classify(domain: str, directory: Directory) -> tuple[str, Service | None]:
    """(class, service). An unknown domain is OPEN, never a shrug."""
    s = directory.lookup(domain)
    return (s.klass if s else UNKNOWN), s
