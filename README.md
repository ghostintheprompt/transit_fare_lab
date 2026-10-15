# transit_fare_lab

A reproducible lab for vulnerability classes in digital transit-fare systems
(contactless fare apps — OMNY, IDFM/Navigo, and the like), built the same way
as [`cve_lab`](../cve_lab): one case per directory, a vulnerable version and
a fixed version of the same server, and a two-part test (functionality +
vulnerability) run against both, not just described.

## Why this exists

Transit fare went from physical tokens and mag-stripe tricks — where the
worst case was a free ride — to phone-linked accounts carrying payment and
location data for an entire metro population, shipped across multiple
separately-contracted vendors with no single engineering org forcing their
schemas (or their security assumptions) to stay in lockstep. That shift is
under-tested relative to its blast radius.

Two of the cases below are not invented — they model vulnerability classes
**confirmed live, non-destructively, against the real `omny.info` account
portal** during an authorized-scope engagement (full report:
[`../CYBER_BENCH_omny_disclosure.md`](../CYBER_BENCH_omny_disclosure.md),
disclosure draft: [`../mta_disclosure_email.md`](../mta_disclosure_email.md)).
That engagement stopped exactly where touching another account's real data
would start — no privilege was gained, no other account was accessed. This
lab is where the next step of that work actually happens: against a system
built for the purpose, where proving the boundary all the way through is
fair game.

## Cases

- [`01-idor-card-balance`](./cases/01-idor-card-balance/) — a card-lookup
  endpoint (`GET /account/wallet/cards/:id`) that checks authentication but
  not authorization: any logged-in user can read any card's balance by ID.
  Models the real OMNY Finding 4 gap (a Luhn-valid, non-sequential card ID
  in the URL, flagged but *not* tested live because confirming it would
  have meant reading another real account's card) — reproduced here against
  a real backend built for the question, and actually answered: the lookup
  is vulnerable until the one ownership check is added.
- [`02-missing-reauth-contact-update`](./cases/02-missing-reauth-contact-update/) —
  email and PIN changes that require a valid session but no password or MFA
  re-confirmation. Models the real OMNY Finding 3 (confirmed live on
  `omny.info`: no re-auth was required at any point in either flow). The
  real engagement's caveat was that this was tested as a fully-authenticated
  user, so the actual exposure — what a *stolen* session token can do with
  nothing further — was inferred, not proven. Here it's proven: the same
  token, with no password supplied, succeeds against the vulnerable server
  and is rejected by the fixed one.

## Running it

Directly:

```bash
npm install
npm test
```

Or containerized:

```bash
docker compose build
docker compose run --rm lab
```

Both run identically — confirmed live, same 8/8 passing output either way.

Each case's `test.js` spins up both the vulnerable and fixed Express app on
an ephemeral local port, runs the same two checks against each, and prints
pass/fail per check, non-destructively against fixture data this lab owns
and seeds itself — nothing in here talks to a real transit system.

## Standing rules for every case added here

Same as `cve_lab`:

- Both the vulnerable and fixed server for a case differ by exactly the
  authorization/authentication check under test — not a rewrite — so the
  diff itself is the finding.
- Exploit demonstrations are non-destructive probes proving a boundary
  holds or doesn't, never a weaponized payload against a system that isn't
  this lab's own fixture data.
- Every claim gets actually run before it's written down as fact.

## Queued next, not started

- A balance/replay case: can a fare-deduction request be replayed to ride
  twice on one charge, or reordered to make balance checks race.
- A session/JWT case modeling the general shape of "cookie theft" as a
  setup step for case 02, instead of case 02 starting from an already-valid
  token.
- IDFM/Navigo-specific case once there's a confirmed, tested finding
  against that system to model, the same way these two model real OMNY
  findings rather than a guess at what IDFM might do.
