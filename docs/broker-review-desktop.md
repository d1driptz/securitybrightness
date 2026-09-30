# Inactive fixture metadata review window

Run from the repository on Windows:

```powershell
python -m core.broker_review_desktop
```

This standalone, opt-in demonstration generates a harmless 37-byte fixture. It
starts no HTTP service and accepts no path, credential, content or command-line
arguments. It does not connect to the child broker transport or read any content.
The existing protected-reader owner walkthrough, `/check` and v1 are unchanged.

The window presents the complete exact request and OS-derived identity metadata
as escaped, read-only JSON. The pathname is only a display label. Click DENY, or
type exactly `ALLOW ONCE` and click `Record ALLOW ONCE evidence`. Enter alone does
not approve. A queued answer is explicitly distinguished from a successfully
recorded answer: the coordinator rechecks freshness before recording evidence.
Closing the window cancels the request. The fixed 30-second handoff deadline is
not renewed by viewing, typing or answering. Rerun for another fresh session.

After a recorded decision the demonstration closes the session and discards the
review evidence. Every outcome releases zero protected bytes. This UI demonstrates
operator review orchestration, not a new enforcement experiment. Automated real
Tk widget tests are separate from a person completing this demonstration.

## Trust and remaining gates

This implements the trusted local operator bootstrap in decision 0001, option A.
The Python process, OS session, Tk UI, bootstrap, registry, coordinator and native
identity collector remain trusted. Operator-port possession is logical role
separation, not independent human identity authentication. Hostile same-process
code or same-user UI automation is outside this claim. A button or child process
does not solve option B.

The UI receives the operator port and completion future; application credentials
remain in the trusted bootstrap. Request text is never executable markup, and
control/bidi characters remain escaped. The fixed synthetic setup creates an
in-memory application grant solely for metadata review; it is never persisted or
used to authorize acquisition. Neither grant nor operator evidence can cause a read.

Before connecting this to a broker, solve the authenticated live observation-to-
review mapping and deliberately bounded human-wait lifecycle. The current child
diagnostic has a ten-second watchdog and must not be extended implicitly by this
UI. Active acquisition would additionally require exact current authority,
resource/effect, freshness, revocation, cancellation, one-use consumption and
delivery checks. This milestone supplies none of those activation permissions.
