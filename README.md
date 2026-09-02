# downstream

**What does your email actually open?** Nobody knows, including you. This counts
it, on your own machine, and shows you the order somebody would take things in.

```
python3 -m downstream --maildir ~/Library/Mail --me you@example.com
```

That is the whole thing. No account, no signup, no upload. It reads message
**headers only**, works out which services you hold accounts with, joins that
against the public [2FA Directory](https://2fa.directory), and writes one HTML
file you open locally.

```
  reading headers only - 41,208 messages, no bodies fetched
  1,943 sender domains -> 96 look like accounts
  joined against 2fa.directory (2,569 services, cached)
  walking the graph from your inbox...
  wrote ~/.downstream/report.html

  91 of 96 accounts are reachable from your inbox, 34 of them in one hop.
  4 changes would disconnect 61 of them. The first is your mobile carrier.
```

---

## Why

Of the 2,569 services in the 2FA Directory, **685 have no second factor at all** —
for those, an inbox is the entire lock. Filtered to services that hold money,
**438 of 787 (56%)** offer nothing better than SMS or an emailed code, so they
are reachable from a mailbox and nothing else. That list includes payroll
providers and student-loan servicers.

Nobody is telling you *which of those you personally have an account with*, and
the answer has been sitting unread in your own mailbox the whole time.

**And it is not a list, it is a graph.** Some accounts are themselves keys:

```
your inbox  ->  your mobile carrier   (resets by email, no 2FA)
            ->  your bank             (its "strong" 2FA is an SMS code)
```

Your bank is two hops from your inbox and the weak link is your phone company.
That is the ordinary SIM-swap chain, it is how people actually lose money, and no
personal tool draws it. "Blast radius" is a real term of art — it has just only
ever been computed for corporate networks, never for a person.

## What it does with what it finds

Ranked by **how many hops away**, not by a severity guess: a thing one step from
your inbox needs no cleverness from anybody.

Then **the moves** — a greedy set-cover over the graph, which is the smallest set
of changes that disconnects the most accounts. It usually puts something you
would never have guessed at the top, because it favours the node other paths run
*through* rather than the one that sounds frightening. 96 accounts is despair.
Four moves is an evening.

## Privacy, as a property of the code

- **Read-only.** IMAP uses `select(readonly=True)` and
  `BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)]`. Nothing is marked as read and
  nothing is written back. Only those three header fields cross the wire at all.
- **No bodies, and no subjects either.** Each subject is classified as it goes
  past and only the *class counts* are kept. The file it writes contains
  domains, dates, counts. Nothing else — there is a test that greps for leaks.
- **Nothing is uploaded.** The only network call in the tool is a GET for a
  public JSON file, which is never asked anything about you.
- **It never contacts a service you have an account with.** No account-existence
  probes, no reset requests fired at third parties, no enumeration. Reading your
  mail and joining public data is the whole method.
- `0600` on everything it writes, set at creation rather than after.
- `downstream --forget` deletes everything it has ever written about you.

There will never be a hosted version. The moment a server sees a mailbox this
becomes the thing it was built against.

## LIMITS

Read this part. It is the honest half.

**It shows what a service OFFERS, not what you switched on.** If your bank
supports an authenticator app and you never enabled it, it appears here as safe
and is not. This is a map of your best possible defence; the real one is at best
this good. The report says so at the top, every time.

**It can only see services that have emailed you.** An account you opened and
never heard from again is invisible. So is anything older than your mailbox
history, and anything you signed up for with a different address.

**English only.** The subject-line rules are English. A German or Spanish mailbox
will under-report, which fails in the direction of saying too little.

**The carrier list is mine, curated, and incomplete.** The 2FA Directory has no
`telecom` keyword — carriers are filed under `utilities` alongside electricity
companies and broadband, and saying "your power company can SIM-swap you" would
be worse than saying nothing. So the SIM edge fires only on an explicit list in
`policy.CARRIER_DOMAINS`. If your provider is missing, `--carrier yours.com`.

**The vault edge is conditional and drawn dashed.** A password manager is a key
to any TOTP account *if your codes live in it* — and whether they do is not
visible in a mail header and never will be. So that path is marked as needing an
assumption rather than asserted. Reject it if it does not hold for you.

**The identification numbers are measured on synthetic mailboxes, not real
ones.** 19 hand-labelled senders across three fixtures, one of which was written
specifically to break the classifier. It did: 80% precision on the first run,
which found two real defects (a payslip matching nothing, and a colleague's
`Re: the invoice` counted as a service). Those are fixed and it is 100% now — but
the rules were adjusted *after* seeing those cases, so this is a corpus that has
been fitted. It is not a claim about your mailbox.

**The carrier also conditionally reaches app-protected accounts, and that edge
is narrower than it first looks.** Some authenticators register a new device
against your phone number, so a SIM swap can reach the codes themselves and
"this service offers an authenticator app" becomes true and irrelevant. Wren
found this class and he was right that leaving it out is not neutral.

But the specific claim needs correcting, and I shipped it before checking, which
is the wrong order:

- **Authy is exposed but not by default.** Twilio turned multi-device *off* by
  default after the 2022 breach, and encrypted backups need a separate password
  on top of the SMS device registration. The vector is real and opt-in, not the
  standing state of every Authy user.
- **Google Authenticator and Microsoft Authenticator do not key on a phone
  number at all.** They restore from a Google account and a personal Microsoft
  account respectively. A SIM swap does not reach those; a takeover of the cloud
  account does — which is the *federated* gap below, not this edge.

So this path is dashed, narrowly worded, and rejectable. If your authenticator
restores from a cloud account rather than a phone number, ignore it here and
read the federated gap instead.

**A consequence of that: the ordering APP-above-PHONE is a claim about what the
service offers, not about you.** It stops being true the moment recovery is
delegated somewhere with a weaker link.

**Two gaps that are named and NOT closed.** Both from the same review:

- *Registrar is not the same as DNS host.* The `mx` edge fires on a registrar
  account, but plenty of self-hosted domains are registered at one company and
  nameservered at another, and it is the nameserver holder who can repoint MX.
  The directory has no "DNS host" keyword, the same way it has no "telecom" one.
- *Federated login is not modelled at all, and it is probably the biggest thing
  missing.* An OPEN Google account is a skeleton key to everything you have ever
  used "Sign in with Google" for, and no hardware key on the downstream service
  can stop it. It is not built because the signal the vault edge rides on does
  not exist for SSO providers - Google, Apple and Microsoft carry keywords like
  `retail`, `backup` and `cloud` in this dataset, never `identity` - so it would
  need a second hardcoded list. That is a separate piece of work, not a cheap
  sibling of what is here.

**Unknown is scored as OPEN.** A service not in the directory is counted as the
bad case. Absence of evidence does not downgrade a risk here, so expect the
report to be pessimistic about anything obscure.

## Running the tests

```
python3 tests/test_downstream.py
```

Every fixture is a real Maildir on disk read by the real reader, and every
service named is a real directory entry with the class it really has. The two
that matter:

- **the planted chain** — inbox → Vodafone [AU] (no 2FA) → Ally Bank (SMS only).
  If that path is not found at depth 2, the graph is decoration.
- **the negative control** — a mailbox where every account is on a hardware key
  must come back with *nothing reachable*. A ranker that alarms everybody is not
  a ranker, and this is the case where the honest answer is "you are fine".

All six load-bearing rules have been mutation-tested: scoring UNKNOWN as safe,
treating an emailed code as real protection, removing the SIM edge, ranking the
moves by severity instead of coverage, and writing subjects to disk, and dropping
the carrier-to-app edge each make a named test go red.

## Credits

Second-factor data from **[2fa.directory](https://2fa.directory)**, MIT licensed,
fetched once and cached. It is maintained by people who care and it is the reason
this tool is a night's work rather than a year's. If a service's entry is wrong,
the fix is a pull request to them.

MIT. Built by [Iris](https://github.com/Soulful-Iris).
