"""The traversal. Every other tool stops at "here are your accounts."

The real world does not stop there, because some accounts are themselves keys.
Your mobile carrier resets by email. Your bank's second factor is SMS. So the
bank's "strong" 2FA is worth exactly what the carrier account is worth, and the
path is two hops. That is the ordinary SIM-swap chain, it is how people actually
lose money, and no personal tool draws it.

So this is a graph, not a list. Breadth-first from the inbox; depth is what
ranks, because a thing one hop away needs no cleverness from anybody.

WHERE THE PRD WAS WRONG, and it changed the design:

  * It said carriers come from a `telecom` keyword. There is no such keyword.
    See policy.CARRIER_DOMAINS.
  * It said the vault edge covers "accounts whose recovery address is that
    vendor". Recovery addresses are not visible in headers and never will be, so
    that edge as specified cannot be built. What replaced it is a CONDITIONAL
    edge with a stated condition, drawn differently on the page, so a reader can
    reject it. Inventing an edge I cannot observe would have been worse than
    leaving it out; asserting it silently would have been worse still.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from . import policy

ROOT = "your email"

# Mail providers nobody registers themselves. If your address is at one of these,
# no registrar account of yours controls its DNS, so the MX edge cannot exist.
PUBLIC_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "icloud.com", "me.com", "mac.com", "yahoo.com", "ymail.com",
    "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.de",
    "web.de", "zoho.com", "fastmail.com", "hey.com", "mail.com", "yandex.com",
    "tutanota.com", "tuta.com", "qq.com", "163.com", "126.com", "naver.com",
}

# Edge kinds, and whether the tool can actually observe them.
RESET = "reset"        # owning the inbox resets this outright
SIM = "sim"            # owning the carrier defeats an SMS second factor
MX = "mx"              # owning the registrar redirects the mail itself
VAULT = "vault"        # conditional: if the codes live in this vault
AUTHBACKUP = "authbackup"   # conditional: if the TOTP codes restore over SMS
CERTAIN = {RESET, SIM, MX}


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    why: str

    @property
    def certain(self) -> bool:
        return self.kind in CERTAIN


@dataclass
class Node:
    domain: str
    name: str
    klass: str
    service: object = None
    why_account: str = ""
    depth: int | None = None
    path: list = field(default_factory=list)     # list[Edge] from ROOT

    @property
    def reachable(self) -> bool:
        return self.depth is not None

    @property
    def only_conditional(self) -> bool:
        """Reached, but only along a path that needs an assumption to hold."""
        return self.reachable and any(not e.certain for e in self.path)


@dataclass
class Graph:
    nodes: dict
    edges: list
    email_domain: str = ""

    def reached(self):
        return [n for n in self.nodes.values() if n.reachable]

    def at_depth(self, d: int):
        return [n for n in self.nodes.values() if n.depth == d]


def build(accounts: dict, directory: policy.Directory, email_domain: str = "") -> Graph:
    """accounts: {domain: read.Sender} that identify.py accepted."""
    nodes: dict[str, Node] = {}
    for d, s in accounts.items():
        klass, svc = policy.classify(d, directory)
        nodes[d] = Node(
            domain=d,
            name=svc.name if svc else d,
            klass=klass,
            service=svc,
            why_account=getattr(s, "why", ""),
        )

    edges: list[Edge] = []
    carriers = [n for n in nodes.values() if n.service and n.service.is_carrier]
    registrars = [n for n in nodes.values() if n.service and n.service.is_registrar]
    vaults = [n for n in nodes.values() if n.service and n.service.is_identity]

    for n in nodes.values():
        # 1. The inbox resets it outright.
        if n.klass in (policy.OPEN, policy.THEATRE, policy.UNKNOWN):
            edges.append(Edge(ROOT, n.domain, RESET, {
                policy.OPEN: "no second factor exists, so a reset link is the whole lock",
                policy.THEATRE: "the only second factor is an emailed code, and the "
                                "attacker is reading the email",
                policy.UNKNOWN: "not in the directory - counted as the bad case, "
                                "because an unknown lock is not a lock",
            }[n.klass]))

    # 2. The carrier defeats every SMS second factor.
    for c in carriers:
        for n in nodes.values():
            if n is c or n.klass != policy.PHONE:
                continue
            edges.append(Edge(c.domain, n.domain, SIM,
                              "its second factor is SMS, and whoever holds the "
                              "carrier account holds the number"))

    # 3. The registrar redirects the mail itself - but only if the address is at
    #    a domain somebody actually registered.
    self_hosted = bool(email_domain) and email_domain.lower() not in PUBLIC_MAIL
    if self_hosted:
        for r in registrars:
            edges.append(Edge(r.domain, ROOT, MX,
                              f"it can repoint the MX records for {email_domain}, "
                              f"which is every address at that domain"))

    # 4. Conditional: the carrier ALSO reaches app-protected accounts, IF the
    #    authenticator restores over SMS. Wren's finding, and he is right that
    #    leaving it out is not neutral:
    #
    #      "Authy restores your entire seed vault to a new device via SMS to the
    #       number on the account. Google Authenticator has synced to a Google
    #       account since 2023; Microsoft Authenticator backs up to a Microsoft
    #       account. In every one of those cases 'the account offers TOTP' is
    #       true and also irrelevant."
    #
    #    It is the same shape the whole tool is built around - your bank's strong
    #    2FA is worth what the carrier is worth - and I stopped one hop short.
    #    Conditional and dashed, like the vault edge, because whether somebody's
    #    codes are actually synced is not visible in a mail header.
    for c in carriers:
        for n in nodes.values():
            if n is c or n.klass != policy.APP:
                continue
            edges.append(Edge(c.domain, n.domain, AUTHBACKUP,
                              "IF your authenticator app restores its codes over "
                              "SMS - Authy does, by default - then holding the "
                              "phone number holds the codes too"))

    # 5. Conditional: a password vault, IF the authenticator codes are in it.
    for v in vaults:
        for n in nodes.values():
            if n is v or n.klass != policy.APP:
                continue
            edges.append(Edge(v.domain, n.domain, VAULT,
                              "IF your authenticator codes are stored in this "
                              "vault, they are not a second factor any more"))

    g = Graph(nodes=nodes, edges=edges, email_domain=email_domain)
    walk(g)
    return g


def walk(g: Graph) -> None:
    """Breadth-first from ROOT, recording the shortest path to each node.

    BFS and not a weighted search on purpose: the number that matters to a
    person is how many steps away a thing is, and every step here is "and then
    they do the obvious next thing".
    """
    out: dict[str, list[Edge]] = {}
    for e in g.edges:
        out.setdefault(e.src, []).append(e)

    for n in g.nodes.values():
        n.depth, n.path = None, []

    seen = {ROOT}
    q = deque([(ROOT, 0, [])])
    while q:
        cur, depth, path = q.popleft()
        for e in out.get(cur, []):
            if e.dst in seen:
                continue
            seen.add(e.dst)
            nxt = path + [e]
            if e.dst == ROOT:
                # An edge back into the inbox does not give the inbox a depth;
                # it means this node is ANOTHER way in, which the page says
                # separately rather than pretending the root was discovered.
                continue
            node = g.nodes.get(e.dst)
            if node is None:
                continue
            node.depth, node.path = depth + 1, nxt
            q.append((e.dst, depth + 1, nxt))


# --- the four moves ----------------------------------------------------------

@dataclass
class Move:
    domain: str
    name: str
    covers: list          # domains that stop being reachable
    action: str
    reason: str


def _reachable_without(g: Graph, blocked: set) -> set:
    """Which domains are still reachable if `blocked` were hardened."""
    out: dict[str, list[Edge]] = {}
    for e in g.edges:
        if e.src in blocked or e.dst in blocked:
            continue
        out.setdefault(e.src, []).append(e)
    seen, q = {ROOT}, deque([ROOT])
    while q:
        cur = q.popleft()
        for e in out.get(cur, []):
            if e.dst not in seen:
                seen.add(e.dst)
                q.append(e.dst)
    return seen - {ROOT}


def _action_for(n: Node) -> tuple[str, str]:
    s = n.service
    if s and s.is_carrier:
        return ("Put a port-out PIN / account PIN on this line, and an "
                "authenticator app on the account if one is offered.",
                "This is the account that turns every SMS code into a formality.")
    if n.klass == policy.HARDWARE:
        return ("Register a security key.", "It offers one and it is the strongest thing here.")
    if n.klass == policy.APP:
        return ("Turn on the authenticator app.", "It offers one; email alone should not be enough.")
    if n.klass == policy.PHONE:
        return ("Only SMS is offered. Secure the phone line itself, above.",
                "Nothing stronger exists on this service.")
    if n.klass == policy.THEATRE:
        return ("Nothing stronger is offered. Use an address nobody knows for "
                "this one, or do not keep anything here you would miss.",
                "An emailed code is not a second factor against someone in your email.")
    if n.klass == policy.UNKNOWN:
        return ("Go and look at its security settings - it is not in the "
                "directory, so nobody has checked.",
                "Unknown is counted as the bad case here.")
    return ("Nothing stronger is offered. Use an address nobody knows for this "
            "one, or do not keep anything here you would miss.",
            "There is no second factor to turn on.")


def moves(g: Graph, k: int = 4) -> list[Move]:
    """Greedy set-cover: the smallest set of changes that disconnects the most.

    Each candidate is "harden this one account". Its value is how many accounts
    stop being reachable, which is 1 for a leaf and a whole subtree for a node
    that other paths run through. That is what makes a carrier outrank a bank in
    the list even though the bank is the thing you care about.
    """
    reachable = {n.domain for n in g.reached()}
    if not reachable:
        return []
    chosen: set = set()
    out: list[Move] = []
    for _ in range(k):
        best, best_gain = None, 0
        still = _reachable_without(g, chosen)
        for d in sorted(still):
            gain = len(still - _reachable_without(g, chosen | {d}))
            if gain > best_gain or (gain == best_gain and best is None):
                best, best_gain = d, gain
        if not best or best_gain <= 0:
            break
        covered = sorted(still - _reachable_without(g, chosen | {best}))
        chosen.add(best)
        n = g.nodes[best]
        action, reason = _action_for(n)
        out.append(Move(domain=best, name=n.name, covers=covered,
                        action=action, reason=reason))
    return out
