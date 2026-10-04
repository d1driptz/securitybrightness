"""Inactive local composition: native metadata retirement, never acquisition.

Trusted bootstrap transfers an exact session, issued observation and reservation
owner. No paths, handles, verifier callbacks, reads or child commands are accepted.
This is not the cross-process acquisition transition and must not authorize one.
"""
from threading import RLock
from .broker_acquisition_draft import AcquisitionDraft, AcquisitionDraftError
from .broker_session import BrokerResourceSession, SessionObservation
from .json_input import loads
from .structured_proposal import StructuredActionProposal


class NativeRetirementError(ValueError):
    pass


class NativeRetirementDraft:
    def __init__(self, acquisition, session, observation):
        if (type(acquisition) is not AcquisitionDraft
                or type(session) is not BrokerResourceSession
                or type(observation) is not SessionObservation):
            raise TypeError('exact local owners required')
        self._acquisition, self._session, self._observation = acquisition, session, observation
        self._lock = RLock()
        self._closed = False

    def retire_once(self, reservation, application_id, credential, proposal):
        """Return only inactive consumption evidence after native retirement.

        Lock order: composition, acquisition, review, registry, ledger, session.
        The first attempt retires both owners, including on invalid input. Native
        cleanup precedes the final authority checks; no receipt survives failure.
        """
        with self._lock:
            try:
                if self._closed: raise NativeRetirementError('unavailable')
                self._closed = True
                acquisition = self._acquisition
                review = acquisition._review
                with acquisition._lock, review._lock, review._lease(), review._ledger._lock:
                    if (acquisition._closed or acquisition._attempted
                            or reservation is not acquisition._issued
                            or not acquisition._matches(reservation)):
                        raise AcquisitionDraftError('invalid_reservation')
                    acquisition._live('acquisition_reserved')
                    if (type(application_id) is not str or type(credential) is not str
                            or not 1 <= len(credential) <= 512
                            or type(proposal) is not StructuredActionProposal
                            or review._registry.authenticate(application_id, credential) is not review._app
                            or proposal.canonical_bytes() != review._proposal_snapshot):
                        raise NativeRetirementError('request_mismatch')
                    # Parse the saved, bounded context, never requester bytes.
                    context = loads(acquisition._snapshot[1])
                    description = self._session.inspect(self._observation, application_id,
                                                        proposal, context['decision_id'])
                    expected = dict(registry_session=self._observation.session_id,
                        owner_session=description.session, resource_token=description.resource_token,
                        volume_serial=description.volume_serial, file_id=description.file_id.hex(),
                        size_bytes=description.size_bytes)
                    if (any(context[name] != value for name, value in expected.items())
                            or review._shown.display_path != description.display_path):
                        raise NativeRetirementError('resource_mismatch')
                    acquisition._live('acquisition_reserved')
                    self._session.verify_once(context['registry_session'], context['resource_token'],
                                              application_id, proposal, context['decision_id'])
                    self._session.close()
                    # Reauthenticates and catches changes during native calls or
                    # cleanup, including revocation, expiry and token mutation.
                    return acquisition.adapter.consume(reservation, application_id, credential, proposal)
            except Exception:
                self.close()
                raise NativeRetirementError('native_retirement_rejected') from None

    def close(self):
        with self._lock:
            self._closed = True
            try:
                self._session.close()
            finally:
                self._acquisition.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
