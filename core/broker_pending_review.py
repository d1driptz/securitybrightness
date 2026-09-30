"""Inactive pending operator-review evidence over local generated resources.

Not wired to broker IPC, /check, the existing reader or any execution path.
Neither recording nor consuming review evidence grants permission or reads data.
"""
from dataclasses import dataclass, asdict, field
import secrets
from threading import RLock
from time import monotonic
from .broker_protocol import _canonical
from .broker_session import BrokerResourceSession
from .file_read_review import FileReadReviewLedger
from .file_read_schema import inspect_file_read_proposal
from .registry import ApplicationRegistry
from .registry_bound_review import RegistryBoundFileReadReviews
from .structured_proposal import StructuredActionProposal


class PendingReviewError(ValueError):
    pass


@dataclass(frozen=True)
class PendingRequest:
    request_id: str
    def __bool__(self): raise TypeError('A request is not permission')


@dataclass(frozen=True)
class PendingDisplay:
    request_id: str
    application_id: str
    proposal_id: str
    draft_id: str
    draft_revision: int
    grant_id: str
    registry_session: str
    owner_session: str
    resource_token: str
    volume_serial: int
    file_id: str
    size_bytes: int
    max_bytes: int
    display_path: str = field(repr=False)
    proposal_json: str = field(repr=False)
    def __bool__(self): raise TypeError('A review display is not permission')


@dataclass(frozen=True)
class ReviewRecorded:
    decision: str
    meaning: str = 'operator evidence only'
    def __bool__(self): raise TypeError('A recorded review is not permission')


@dataclass(frozen=True)
class RetiredReviewEvidence:
    canonical_display: bytes = field(repr=False)
    decision: str = 'allow_once'
    lifecycle: str = 'retired'
    meaning: str = 'review evidence only; no operation authorized'
    def __bool__(self): raise TypeError('Review evidence is not permission')


class _ApplicationPort:
    def __init__(self, owner): self._owner=owner
    def propose(self, application_id, credential, proposal, draft_id, revision):
        return self._owner._begin(application_id,credential,proposal,draft_id,revision)
    def consume_evidence(self, request, application_id, credential, proposal):
        return self._owner._consume(request,application_id,credential,proposal)


class _OperatorPort:
    def __init__(self, owner): self._owner=owner
    def display(self, request): return self._owner._display(request)
    def record(self, display, decision): return self._owner._record(display,decision)
    def cancel(self): self._owner.close()


class PendingBrokerReview:
    """One pending request per trusted host instance; no restoration or renewal.

    Host must distribute operator/application ports separately. This is logical
    role separation, not operator identity authentication or hostile-Python isolation.
    Lock order: coordinator -> registry -> draft ledger -> broker ownership.
    """
    def __init__(self, registry, ledger):
        if type(registry) is not ApplicationRegistry or type(ledger) is not FileReadReviewLedger:
            raise TypeError('expected current registry and draft ledger')
        self._registry,self._ledger=registry,ledger
        self._reviews=RegistryBoundFileReadReviews(registry,ledger)
        self._broker=BrokerResourceSession(capacity=1)
        self._lock=RLock()
        self._closed=False
        self._request=self._ticket=self._shown=None
        self._decision=None
        self.application=_ApplicationPort(self)
        self.operator=_OperatorPort(self)

    def _deadline_check(self):
        if monotonic()>=self._deadline: raise PendingReviewError('expired')

    def _draft_state(self):
        draft=self._ledger._existing(self._ticket.review.draft_id)
        return (draft.draft_id,draft.revision,draft.revoked,_canonical(draft.constraint.to_payload()))

    def _authority(self):
        self._deadline_check()
        with self._lease():
            if (_canonical(asdict(self._ticket))!=self._ticket_snapshot
                    or not self._reviews.check_review(self._ticket,self._app.application_id,self._proposal).current
                    or self._draft_state()!=self._draft_snapshot
                    or not ({'files.read','*'} & self._app.scopes)):
                raise PendingReviewError('authority_or_draft_changed')
        self._deadline_check()

    def _current(self):
        self._authority()
        description=self._broker.inspect(self._observation,self._app.application_id,self._proposal,self._identity)
        self._authority()
        return description

    def _check_request(self, request):
        if (self._closed or request is not self._request or type(request) is not PendingRequest
                or request.request_id!=self._identity):
            raise PendingReviewError('unknown_request')

    def _begin(self, application_id, credential, proposal, draft_id, revision):
        with self._lock:
            try:
                if self._closed or self._request is not None or type(proposal) is not StructuredActionProposal:
                    raise PendingReviewError('unavailable')
                if type(credential) is not str or not 1<=len(credential)<=512:
                    raise PendingReviewError('invalid_credential')
                self._app=self._registry.authenticate(application_id,credential)
                if self._app is None or not ({'files.read','*'} & self._app.scopes):
                    raise PendingReviewError('authority_unavailable')
                self._lease=self._registry.authorization_lease(self._app)
                with self._lease(),self._ledger._lock:
                    self._proposal=proposal
                    self._identity=secrets.token_hex(32)
                    self._deadline=monotonic()+60
                    self._ticket=self._reviews.begin_review(application_id,credential,proposal,draft_id,revision)
                    self._ticket_snapshot=_canonical(asdict(self._ticket))
                    self._draft_snapshot=self._draft_state()
                    self._observation=self._broker.issue(application_id,proposal,self._identity)
                    self._current()
                    self._request=PendingRequest(self._identity)
                    return self._request
            except Exception:
                self.close()
                raise PendingReviewError('request_unavailable') from None

    def _display(self, request):
        with self._lock:
            try:
                self._check_request(request)
                with self._lease(),self._ledger._lock:
                    description=self._current()
                    intent=inspect_file_read_proposal(self._proposal)
                    display=PendingDisplay(self._identity,self._app.application_id,intent.proposal_id,
                        self._ticket.review.draft_id,self._ticket.review.revision,self._ticket.grant_id,
                        self._observation.session_id,description.session,description.resource_token,
                        description.volume_serial,description.file_id.hex(),description.size_bytes,intent.max_bytes,
                        description.display_path,self._proposal.canonical_bytes().decode('ascii'))
                    self._shown=display
                    self._shown_snapshot=_canonical(asdict(display))
                    self._decision=None  # Redisplay never carries forward review evidence.
                    self._deadline_check()
                    return display
            except Exception:
                self.close()
                raise PendingReviewError('display_unavailable') from None

    def _record(self, display, decision):
        with self._lock:
            try:
                if (self._closed or type(display) is not PendingDisplay or display is not self._shown
                        or _canonical(asdict(display))!=self._shown_snapshot or self._decision is not None
                        or type(decision) is not str or decision not in {'allow_once','deny'}):
                    raise PendingReviewError('invalid_review')
                with self._lease(),self._ledger._lock:
                    self._current()
                    self._decision=decision
                    result=ReviewRecorded(decision)
                    if decision=='deny': self.close()
                    self._deadline_check()
                    return result
            except Exception:
                self.close()
                raise PendingReviewError('review_unavailable') from None

    def _consume(self, request, application_id, credential, proposal):
        with self._lock:
            try:
                self._check_request(request)
                # First attempt is terminal, including absence of review evidence.
                self._closed=True
                if (type(credential) is not str or not 1<=len(credential)<=512
                        or type(proposal) is not StructuredActionProposal
                        or proposal.canonical_bytes()!=self._proposal.canonical_bytes()
                        or self._registry.authenticate(application_id,credential) is not self._app
                        or self._decision!='allow_once'
                        or _canonical(asdict(self._shown))!=self._shown_snapshot):
                    raise PendingReviewError('evidence_unavailable')
                with self._lease(),self._ledger._lock:
                    self._current()
                    self._broker.verify_once(self._observation.session_id,self._observation.resource_token,
                        application_id,proposal,self._identity)
                    self._authority()
                    self._reviews.discard_review(self._ticket)
                    # Detect same-thread fault injection during evidence retirement;
                    # other threads are held behind the registry/ledger locks here.
                    with self._lease():
                        if self._draft_state()!=self._draft_snapshot:
                            raise PendingReviewError('draft_changed')
                        result=RetiredReviewEvidence(self._shown_snapshot)
                        self._deadline_check()
                        return result
            except Exception:
                self.close()
                raise PendingReviewError('evidence_unavailable') from None

    def close(self):
        with self._lock:
            self._closed=True
            try: self._broker.close()
            finally:
                if self._ticket is not None: self._reviews.discard_review(self._ticket)
                self._decision=None

    def __enter__(self): return self
    def __exit__(self,*_): self.close()
