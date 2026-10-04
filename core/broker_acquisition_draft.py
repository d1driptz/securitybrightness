"""Inactive one-use acquisition reservation model; not executable permission.

Only an exact live diagnostic review can be reserved. Retired receipts, requester
claims and stored tokens cannot issue authority. No host/child/reader imports this
module. Consumption proves current coordinator state only, not fresh OS identity,
broker liveness, permission to read or permission to publish bytes.
"""
from dataclasses import dataclass, asdict, field
import hashlib
import secrets
from threading import RLock
from time import monotonic
from .broker_live_review import LiveBrokerReview
from .broker_protocol import _canonical
from .broker_quarantine import _context
from .structured_proposal import StructuredActionProposal


class AcquisitionDraftError(ValueError):
    pass


@dataclass(frozen=True)
class AcquisitionReservation:
    reservation_id: str
    canonical_context: bytes = field(repr=False)
    display_digest: str
    def __bool__(self): raise TypeError('An inactive reservation is not executable permission')


@dataclass(frozen=True)
class ConsumedAcquisitionDraft:
    reservation_id: str
    context_digest: str
    meaning: str = field(default='inactive consumption evidence; no read or delivery authorized', init=False)
    def __bool__(self): raise TypeError('Consumption evidence is not read or delivery permission')


class _CoordinatorPort:
    def __init__(self, owner): self._owner = owner
    def reserve(self): return self._owner._reserve()
    def cancel(self): self._owner.close()


class _AdapterPort:
    def __init__(self, owner): self._owner = owner
    def consume(self, reservation, app, credential, proposal):
        return self._owner._consume(reservation, app, credential, proposal)


class AcquisitionDraft:
    """One reservation and one attempt. No extension, restoration or reassignment.

    Trusted bootstrap distributes ports separately. Locks: reservation -> review
    -> registry -> draft ledger. The exact diagnostic source is deliberately
    required; the production metadata host's review subclass is not accepted.
    This uses private review invariants and must be reviewed with that model.
    Reserving transfers source ownership: callers must cancel/join their transport
    when this model closes; it does not own or terminate a broker process itself.
    """
    def __init__(self, review):
        if type(review) is not LiveBrokerReview:
            raise TypeError('expected exact live diagnostic review')
        self._review = review
        self._lock = RLock()
        self._closed = self._attempted = False
        self._issued = None
        self.coordinator, self.adapter = _CoordinatorPort(self), _AdapterPort(self)

    def _live(self, state):
        review = self._review
        review._current(state)
        if (review._decision != 'allow_once' or review._shown is not review._facts
                or _canonical(asdict(review._shown)) != review._facts_snapshot):
            raise AcquisitionDraftError('fresh_review_required')

    def _matches(self, token):
        return (type(token) is AcquisitionReservation and type(token.reservation_id) is str
                and type(token.canonical_context) is bytes and type(token.display_digest) is str
                and (token.reservation_id, token.canonical_context, token.display_digest) == self._snapshot)

    def _reserve(self):
        with self._lock, self._review._lock:
            try:
                if self._closed or self._issued is not None: raise AcquisitionDraftError('unavailable')
                review = self._review
                self._live('recorded')
                with review._lease(), review._ledger._lock:
                    self._live('recorded')
                    facts = review._shown
                    identity = secrets.token_hex(32)
                    snapshot = _context(dict(application_id=facts.application_id, proposal_id=facts.proposal_id,
                        grant_id=facts.grant_id, draft_id=facts.draft_id, draft_revision=facts.draft_revision,
                        review_id=identity, decision_id=facts.request_id, registry_session=facts.registry_session,
                        owner_session=facts.owner_session, resource_token=facts.resource_token,
                        volume_serial=facts.volume_serial, file_id=facts.file_id, size_bytes=facts.size_bytes,
                        max_bytes=facts.max_bytes, operation='files.read', recipient='requesting_application'))
                    token = AcquisitionReservation(identity, snapshot, hashlib.sha256(review._facts_snapshot).hexdigest())
                    self._snapshot = (token.reservation_id, token.canonical_context, token.display_digest)
                    self._context_digest = hashlib.sha256(snapshot).hexdigest()
                    self._live('recorded')
                    review._state = 'acquisition_reserved'
                    self._issued = token
                    return token
            except Exception:
                self.close()
                raise AcquisitionDraftError('reservation_rejected') from None

    def _consume(self, token, app, credential, proposal):
        with self._lock, self._review._lock:
            try:
                if self._closed or self._attempted: raise AcquisitionDraftError('unavailable')
                self._attempted = True  # Invalid first attempts also irrevocably consume the slot.
                if (self._issued is None or token is not self._issued or not self._matches(token)
                        or type(credential) is not str or not 1 <= len(credential) <= 512
                        or type(proposal) is not StructuredActionProposal):
                    raise AcquisitionDraftError('invalid_reservation')
                review = self._review
                with review._lease(), review._ledger._lock:
                    self._live('acquisition_reserved')
                    if (review._registry.authenticate(app, credential) is not review._app
                            or proposal.canonical_bytes() != review._proposal_snapshot):
                        raise AcquisitionDraftError('wrong_application_or_proposal')
                    self._live('acquisition_reserved')
                    if not self._matches(token): raise AcquisitionDraftError('changed_reservation')
                    result = ConsumedAcquisitionDraft(self._snapshot[0], self._context_digest)
                    self.close()
                    # Serialize concurrent authority changes and catch same-thread
                    # changes injected during retirement. No live evidence survives.
                    with review._lease():
                        if (not self._matches(token) or review._app_state() != review._app_snapshot or review._draft() != review._draft_snapshot
                                or monotonic() >= review._deadline):
                            raise AcquisitionDraftError('changed_during_retirement')
                    return result
            except Exception:
                self.close()
                raise AcquisitionDraftError('consumption_rejected') from None

    def close(self):
        with self._lock, self._review._lock:
            self._closed = True
            self._issued = None
            self._review.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
