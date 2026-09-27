"""Inactive combined review envelope. Freshness samples never authorize operations.

This pairs a registry-bound review with an adapter-owned resource lifetime. It
accepts no human approval and supplies no execution lease or atomic allow result.
"""
from dataclasses import dataclass, field
from threading import RLock
from uuid import uuid4

from .file_read_review import ReviewFreshness
from .file_read_schema import inspect_file_read_proposal
from .registry_bound_review import RegistryBoundFileReadReviews, RegistryBoundReviewTicket
from .resource_binding import WindowsFileObservation, FileReadOperationBinding
from .validation import application_id as validate_application_id
from .windows_identity import WindowsIdentityCollector


@dataclass(frozen=True)
class ResourceReviewEnvelope:
    envelope_id: str
    application_id: str
    proposal_id: str
    review: RegistryBoundReviewTicket = field(repr=False)
    observation: WindowsFileObservation = field(repr=False)
    binding: FileReadOperationBinding = field(repr=False)
    schema: str = 'resource_review.v1'

    def __bool__(self):
        raise TypeError('A resource review envelope is evidence, never permission')


class ResourceReviewEnvelopes:
    """Trusted-process, bounded evidence pairing; deliberately no allow API.

    Checks sample review state, then the retained resource, then review state
    again. This detects changes between those checks, but is NOT an atomic
    authorization/operation boundary. State can change after any returned sample.
    The collector and review coordinator remain independently owned by the caller.
    """
    def __init__(self, reviews, collector, *, capacity=128):
        if type(reviews) is not RegistryBoundFileReadReviews:
            raise TypeError('expected registry-bound review coordinator')
        if type(collector) is not WindowsIdentityCollector:
            raise TypeError('expected native identity collector')
        if type(capacity) is not int or not 1 <= capacity <= 4096:
            raise ValueError('capacity must be between 1 and 4096')
        self._reviews, self._collector = reviews, collector
        self._capacity = capacity
        self._issued = {}
        self._lock = RLock()
        self._closed = False

    def capture(self, ticket, application_id, proposal, observation):
        application_id = validate_application_id(application_id)
        intent = inspect_file_read_proposal(proposal)
        if type(ticket) is not RegistryBoundReviewTicket or type(observation) is not WindowsFileObservation:
            raise TypeError('expected issued review and native observation')
        with self._lock:
            if self._closed or len(self._issued) >= self._capacity:
                raise ValueError('envelope session unavailable')
            identity = str(uuid4())
            if identity in self._issued:
                raise ValueError('duplicate envelope identity')
            if not self._reviews.check_review(ticket, application_id, proposal).current:
                raise ValueError('review unavailable')
            binding = self._collector.bind(application_id, proposal, observation)
            if not self._reviews.check_review(ticket, application_id, proposal).current:
                raise ValueError('review changed during capture')
            envelope = ResourceReviewEnvelope(identity, application_id, intent.proposal_id,
                                               ticket, observation, binding)
            self._issued[identity] = envelope
            return envelope

    def inspect(self, envelope, application_id, proposal):
        application_id = validate_application_id(application_id)
        intent = inspect_file_read_proposal(proposal)
        with self._lock:
            if (self._closed or type(envelope) is not ResourceReviewEnvelope
                    or type(envelope.envelope_id) is not str
                    or self._issued.get(envelope.envelope_id) is not envelope):
                return ReviewFreshness(False, 'unknown_or_retired_envelope')
            if envelope.application_id != application_id or envelope.proposal_id != intent.proposal_id:
                return ReviewFreshness(False, 'request_mismatch')
            try:
                current = self._reviews.check_review(envelope.review, application_id, proposal).current
                if current:
                    current = self._collector.matches(envelope.binding, application_id, proposal,
                                                      envelope.observation).matches
                if current:
                    current = self._reviews.check_review(envelope.review, application_id, proposal).current
            except Exception:
                current = False
            if not current:
                self._issued[envelope.envelope_id] = None
                return ReviewFreshness(False, 'evidence_changed_or_unavailable')
            return ReviewFreshness(True, 'current_resource_review_sample')

    def discard(self, envelope):
        with self._lock:
            if (type(envelope) is ResourceReviewEnvelope and type(envelope.envelope_id) is str
                    and self._issued.get(envelope.envelope_id) is envelope):
                self._issued[envelope.envelope_id] = None

    def close(self):
        with self._lock:
            self._closed = True
            self._issued.clear()
