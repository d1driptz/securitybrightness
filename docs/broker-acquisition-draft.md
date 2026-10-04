# Inactive one-use acquisition reservation model

`core/broker_acquisition_draft.py` models reservation and consumption of exact live
review state. It does not issue executable read permission, perform I/O, stage data
or publish bytes. No existing host, child, desktop, protected reader or `/check`
path imports it. The verified owner walkthrough is unchanged.

Trusted bootstrap must supply the **exact live diagnostic review object** and
distribute coordinator/adapter ports separately. Retired receipts, stored review
data, requester dictionaries and the existing metadata host's review subclass are
not accepted. Bootstrap/port possession remains option A's trusted local operator
assumption, not independent human authentication or hostile-Python isolation.

## Reservation

The coordinator can reserve once, only while the source has explicit ALLOW ONCE
evidence over its exact issued display. Reservation requires current application
scope, unchanged grant/activation, unchanged draft/revision, exact proposal and
the authenticated observation binding. Application authority alone and review
evidence alone are insufficient.

The immutable context binds application/proposal, grant, draft/revision,
reservation review nonce, decision, broker resource-session/owner/token,
volume/file identity, observed size, maximum bytes and requesting-application
recipient. Paths are excluded from resource identity. The source's display digest
also binds the exact human-facing facts. The new nonce identifies this reservation
over that review; it does not independently authenticate a human.

Reserving moves the source to a distinct `acquisition_reserved` state. The old
metadata finish path cannot bypass it. No deadline is extended: the original
diagnostic review's at-most-five-second lifetime remains authoritative, and its
timer still closes idle state. A duplicate reservation, including through a
second reservation owner, invalidates the source rather than minting another use.

## Consumption and retirement

The adapter port accepts only the exact issued object with unchanged immutable
fields. It reauthenticates the application and exact proposal, then checks current
grant activation, registry snapshot, review/draft state and display again. The
first attempt spends the reservation even if the token, credential or proposal is
invalid. Concurrent attempts have at most one successful result.

Consumption closes the source and discards review state under the review,
registry and ledger locks. Final checks detect expiry, token mutation and
registry/draft changes during retirement. The return value is immutable inactive
consumption evidence only: no data, read command, delivery permission or useful
bearer token. It cannot be replayed, restored or transferred to another application.
This model owns review state, not a process; a future host must cancel and join
its transport on closure. It must not leave the child running after retiring state.

The implementation deliberately relies on private diagnostic-review invariants;
changes to that model require joint review. The existing production metadata host
is not connected, so these tests do not claim a new running authority boundary.

## Remaining gates before activation

An authenticated observation is a report, not proof that the broker still holds
the same resource at consumption time. This model **does not** revalidate a native
handle or establish live broker/resource ownership. Tests use authenticated
synthetic peers and exercise lifecycle semantics without resource access.

Before a reservation can become actual acquisition authority, bind consumption
to a fresh retained-resource validation in the trusted broker and a deliberate
one-use wire transition. Define how cancellation, revocation, expiry, replacement,
lost messages, cleanup failure and child crashes invalidate that transition.
Do not turn this consumption receipt or a retired review into a read command.

After that, bounded quarantine and a separate final publication check must still
withhold all data when authority, human control, identity or lifecycle checks fail.
Only a controlled generated-fixture integration demonstrating that denial prevents
delivery can establish a broker-backed enforcement claim. `/check`, v1, direct
Windows access and the existing protected-reader boundary remain unchanged.
