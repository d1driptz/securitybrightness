"""Inactive authenticated observation/review mapping. No transport or read API.

Trusted bootstrap owns the coordinator port and fresh key/session. The operator
port is distributed separately. This diagnostic's <=5s lifetime is deliberately
shorter than the existing child's 10s watchdog; it is not a desktop human flow.
"""
from dataclasses import dataclass, asdict, field
import hashlib
import math
import secrets
from threading import RLock, Timer
from time import monotonic

from .broker_live_protocol import LiveMetadataExchange
from .broker_pending_review import PendingDisplay, ReviewRecorded
from .broker_protocol import _canonical
from .file_read_review import FileReadReviewLedger
from .file_read_schema import inspect_file_read_proposal
from .registry import ApplicationRegistry
from .registry_bound_review import RegistryBoundFileReadReviews
from .structured_proposal import StructuredActionProposal


class LiveReviewError(ValueError):
    pass


@dataclass(frozen=True)
class RetiredMappedReview:
    canonical_display: bytes = field(repr=False)
    decision: str
    lifecycle: str = field(default='retired', init=False)
    meaning: str = field(default='metadata review only; no operation authorized', init=False)
    def __bool__(self): raise TypeError('Retired review metadata is not permission')


class _CoordinatorPort:
    def __init__(self, owner): self._owner = owner
    def begin(self, app, credential, proposal, draft_id, revision):
        return self._owner._begin(app, credential, proposal, draft_id, revision)
    def observe(self, frame): return self._owner._observe(frame)
    def finish(self): return self._owner._finish()
    def retire(self, frame): return self._owner._retire(frame)
    def cancel(self): self._owner.close()


class _OperatorPort:
    def __init__(self, owner): self._owner = owner
    def display(self): return self._owner._display()
    def record(self, display, answer): return self._owner._record(display, answer)
    def cancel(self): self._owner.close()


class LiveBrokerReview:
    """One authenticated transcript, one exact display, one response, no renewal.

    A MAC proves peer key possession, not identity truth or human permission.
    Only the fixed trusted child may hold the peer key in a future host. Revocation
    checks occur at every transition; no registry lock is held while humans wait.
    Lock order: mapping -> registry -> draft ledger -> private review coordinator.
    Closing this mapping does not close a process: host transport must terminate
    it on cancellation/failure and require EOF, clean exit and cleanup separately.
    """
    def __init__(self, registry, ledger, *, key, session, timeout=5):
        if type(registry) is not ApplicationRegistry or type(ledger) is not FileReadReviewLedger:
            raise TypeError('expected registry and ledger')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_review_lifetime')
        self._exchange = LiveMetadataExchange(role='coordinator', key=key, session=session)
        self._registry, self._ledger, self._timeout = registry, ledger, timeout
        self._reviews = RegistryBoundFileReadReviews(registry, ledger)
        self._lock = RLock()
        self._state = 'new'
        self._ticket = self._timer = self._shown = None
        self.coordinator, self.operator = _CoordinatorPort(self), _OperatorPort(self)

    def _draft(self):
        draft = self._ledger._existing(self._ticket.review.draft_id)
        return (draft.draft_id, draft.revision, draft.revoked, _canonical(draft.constraint.to_payload()))

    def _app_state(self):
        value = asdict(self._app)
        if type(value['scopes']) is not frozenset:
            raise LiveReviewError('corrupt_authority')
        value['scopes'] = sorted(value['scopes'])
        return hashlib.sha256(_canonical(value)).digest()

    def _current(self, expected):
        if self._state != expected or monotonic() >= self._deadline:
            raise LiveReviewError('unavailable')
        with self._lease(), self._ledger._lock:
            if (self._proposal.canonical_bytes() != self._proposal_snapshot
                    or self._app_state() != self._app_snapshot
                    or _canonical(asdict(self._ticket)) != self._ticket_snapshot
                    or self._draft() != self._draft_snapshot
                    or not ({'files.read', '*'} & self._app.scopes)
                    or not self._reviews.check_review(self._ticket, self._app.application_id, self._proposal).current):
                raise LiveReviewError('stale_authority')
        if monotonic() >= self._deadline:
            raise LiveReviewError('expired')

    def _begin(self, app, credential, proposal, draft_id, revision):
        with self._lock:
            try:
                if (self._state != 'new' or type(proposal) is not StructuredActionProposal
                        or type(credential) is not str or not 1 <= len(credential) <= 512):
                    raise LiveReviewError('invalid_request')
                self._deadline = monotonic() + self._timeout
                self._app = self._registry.authenticate(app, credential)
                if self._app is None or not ({'files.read', '*'} & self._app.scopes):
                    raise LiveReviewError('authority_unavailable')
                self._lease = self._registry.authorization_lease(self._app)
                self._proposal = proposal
                self._proposal_snapshot = proposal.canonical_bytes()
                self._identity = secrets.token_hex(32)
                with self._lease(), self._ledger._lock:
                    self._app_snapshot = self._app_state()
                    self._ticket = self._reviews.begin_review(app, credential, proposal, draft_id, revision)
                    self._ticket_snapshot = _canonical(asdict(self._ticket))
                    self._draft_snapshot = self._draft()
                    frame = self._exchange.send(dict(application_id=app, decision_id=self._identity,
                                                    proposal_json=self._proposal_snapshot.decode('ascii')))
                    self._state = 'await_observation'
                    self._current('await_observation')
                self._timer = Timer(max(0, self._deadline-monotonic()), self.close)
                self._timer.daemon = True
                self._timer.start()
                self._current('await_observation')
                return frame
            except Exception:
                self.close()
                raise LiveReviewError('request_rejected') from None

    def _observe(self, frame):
        with self._lock:
            try:
                self._current('await_observation')
                observation = self._exchange.receive(frame)
                self._observation_snapshot = _canonical(observation)
                self._digest = hashlib.sha256(self._observation_snapshot).hexdigest()
                resource = observation['observation']
                if self._identity in {observation['registry_session'], resource['owner_session'], resource['resource_token']}:
                    raise LiveReviewError('identity_collision')
                intent = inspect_file_read_proposal(self._proposal)
                self._facts = PendingDisplay(self._identity, self._app.application_id, intent.proposal_id,
                    self._ticket.review.draft_id, self._ticket.review.revision, self._ticket.grant_id,
                    observation['registry_session'], resource['owner_session'], resource['resource_token'],
                    resource['volume_serial'], resource['file_id'], resource['size_bytes'], intent.max_bytes,
                    resource['display_path'], self._proposal_snapshot.decode('ascii'))
                self._facts_snapshot = _canonical(asdict(self._facts))
                self._current('await_observation')
                self._state = 'observed'
            except Exception:
                self.close()
                raise LiveReviewError('observation_rejected') from None

    def _display(self):
        with self._lock:
            try:
                self._current('observed')
                if _canonical(asdict(self._facts)) != self._facts_snapshot:
                    raise LiveReviewError('changed_display')
                self._current('observed')
                self._shown = self._facts
                self._state = 'shown'
                return self._shown
            except Exception:
                self.close()
                raise LiveReviewError('display_rejected') from None

    def _record(self, display, answer):
        with self._lock:
            try:
                self._current('shown')
                if (type(display) is not PendingDisplay or display is not self._shown
                        or _canonical(asdict(display)) != self._facts_snapshot
                        or type(answer) is not str or answer not in {'ALLOW ONCE', 'DENY'}):
                    raise LiveReviewError('invalid_answer')
                self._decision = 'allow_once' if answer == 'ALLOW ONCE' else 'deny'
                self._current('shown')
                self._state = 'recorded'
                return ReviewRecorded(self._decision)
            except Exception:
                self.close()
                raise LiveReviewError('review_rejected') from None

    def _finish(self):
        with self._lock:
            try:
                self._current('recorded')
                if _canonical(asdict(self._shown)) != self._facts_snapshot:
                    raise LiveReviewError('changed_display')
                # "verify" only verifies and retires metadata; never reads.
                frame = self._exchange.send(dict(action='verify' if self._decision == 'allow_once' else 'cancel',
                                                 observation_digest=self._digest))
                self._current('recorded')
                self._state = 'await_retirement'
                return frame
            except Exception:
                self.close()
                raise LiveReviewError('finish_rejected') from None

    def _retire(self, frame):
        with self._lock:
            try:
                self._current('await_retirement')
                self._exchange.receive(frame)  # Only exact authenticated retired denial.
                with self._lease(), self._ledger._lock:
                    self._current('await_retirement')
                    if _canonical(asdict(self._shown)) != self._facts_snapshot:
                        raise LiveReviewError('changed_display')
                    result = RetiredMappedReview(self._facts_snapshot, self._decision)
                    self.close()
                    # No stale success if retirement itself changes registry/draft state.
                    with self._lease():
                        if (self._draft() != self._draft_snapshot or self._app_state() != self._app_snapshot
                                or monotonic() >= self._deadline):
                            raise LiveReviewError('stale_retirement')
                    return result
            except Exception:
                self.close()
                raise LiveReviewError('retirement_rejected') from None

    def close(self):
        with self._lock:
            self._state = 'closed'
            if self._timer is not None: self._timer.cancel()
            self._exchange.close()
            if self._ticket is not None: self._reviews.discard_review(self._ticket)

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
