"""Inactive fixed native publication-check profile; no application delivery.

This owns only a newly generated fixture. Logical recipient fields are separately
authenticated coordinator claims, not independently observed OS/channel identity.
No existing child/host/product path selects this new profile.
"""
from time import monotonic
from .broker_native_acquisition import NativeFixtureAcquisitionAdapter, NativeAcquisitionError, _NativeReadFixture
from .broker_publication_protocol import PublicationCheckExchange, _publication_binding
from .broker_protocol import _canonical
from .broker_observation import proposal_from_text
from .file_read_schema import inspect_file_read_proposal
from .json_input import loads


class PublicationNativeFixtureAdapter(NativeFixtureAcquisitionAdapter):
    """Fixed original-handle read, exact logical-recipient binding, retire once.

    A trusted coordinator must independently enforce current application/grant,
    human control, exact recipient ownership and final publication. This adapter
    accepts no file/recipient selector, executable, callback or delivery command.
    """
    def __init__(self, *, key, session, timeout=5):
        super().__init__(key=key, session=session, timeout=timeout)
        self._adapter_deadline_snapshot = self._deadline
        self._issued_owner = self._owner_deadline_snapshot = None
        self._issued_wire = None
        self._owner_changed = self._wire_changed = False
        self._binding_snapshot = self._recipient_snapshot = None

    def _check(self, state):
        super()._check(state)
        if (type(self._state) is not str or self._cancelled is not False
                or type(self._deadline) is not float or self._deadline != self._adapter_deadline_snapshot
                or (self._issued_owner is not None and (self._owner is not self._issued_owner
                    or type(self._owner._deadline) is not float
                    or self._owner._deadline != self._owner_deadline_snapshot))):
            raise NativeAcquisitionError('changed_native_owner')

    def _wire_current(self, step):
        wire = self._wire
        if (type(wire) is not PublicationCheckExchange or wire is not self._issued_wire
                or type(wire._step) is not int or wire._step != step
                or type(wire._state) is not str or wire._state != ('closed' if step == 4 else 'new')
                or type(wire._deadline) is not float or wire._deadline != wire._deadline_snapshot
                or monotonic() >= wire._deadline_snapshot):
            raise NativeAcquisitionError('publication_wire_unavailable')
        with wire._lock:
            if step < 4: wire._integrity()
            elif (type(wire._key) is not bytes or wire._key
                    or type(wire._buffer) is not bytearray or wire._buffer
                    or wire._buffer is not wire._issued_buffer):
                raise NativeAcquisitionError('publication_wire_not_closed')
            if self._binding_snapshot is not None:
                if (type(wire._context_snapshot) is not bytes or wire._context_snapshot != self._binding_snapshot
                        or _publication_binding(loads(wire._context_snapshot)) != self._binding_snapshot
                        or _canonical(loads(self._binding_snapshot)['recipient']) != self._recipient_snapshot):
                    raise NativeAcquisitionError('changed_publication_binding')

    def open(self, frame):
        with self._lock:
            try:
                self._check('new')
                request = self._opening.receive(frame)
                self._proposal = proposal_from_text(request['proposal_json'])
                self._request = self._request_snapshot = _canonical(request)
                self._owner = self._issued_owner = _NativeReadFixture()
                self._owner._deadline = min(self._owner._deadline, self._deadline)
                self._owner_deadline_snapshot = self._owner._deadline
                d = self._owner.description
                if request['decision_id'] in {d.registry_session, d.owner_session, d.resource_token}:
                    raise NativeAcquisitionError('identifier_collision')
                if not d.size_bytes <= inspect_file_read_proposal(self._proposal).max_bytes <= 4096:
                    raise NativeAcquisitionError('unsupported_bound')
                self._wire = self._issued_wire = PublicationCheckExchange(role='broker', key=self._key, session=self._session,
                                                       timeout=min(5, self._deadline-monotonic()))
                self._wire_current(0)
                result = self._opening.send(dict(registry_session=d.registry_session, observation=dict(
                    owner_session=d.owner_session, resource_token=d.resource_token,
                    volume_serial=d.volume_serial, file_id=d.file_id, size_bytes=d.size_bytes,
                    display_path=d.display_path)))
                self._opening.close()
                self._owner.validate()
                self._validate_opening()
                self._check('new')
                self._state = 'observed'
                return result
            except Exception: self._abort('publication_opening_rejected')

    def _abort(self, reason):
        try: self.close()
        finally: raise NativeAcquisitionError(reason) from None

    def stage(self, frame):
        with self._lock:
            try:
                self._check('observed')
                self._state = 'acquiring'  # Invalid first attempts are permanently spent.
                binding = self._wire.accept_request(frame).inspect()
                self._binding_snapshot = _publication_binding(binding)
                self._recipient_snapshot = _canonical(binding['recipient'])
                self._wire_current(1)
                self._owner.validate(); self._validate_opening()
                d, request = self._owner.description, self._request_values()
                intent = inspect_file_read_proposal(self._proposal)
                expected = dict(application_id=request['application_id'], proposal_id=intent.proposal_id,
                    decision_id=request['decision_id'], registry_session=d.registry_session,
                    owner_session=d.owner_session, resource_token=d.resource_token,
                    volume_serial=d.volume_serial, file_id=d.file_id, size_bytes=d.size_bytes,
                    max_bytes=intent.max_bytes, operation='files.read', recipient='requesting_application')
                context, recipient = binding['context'], binding['recipient']
                if (any(context[name] != value for name, value in expected.items())
                        or recipient['application_id'] != request['application_id']
                        or recipient['recipient_revision'] != 1):
                    raise NativeAcquisitionError('publication_binding_mismatch')
                self._check('acquiring')
                data = self._owner.acquire_once(context['max_bytes'])
                self._check('acquiring')
                result = self._wire.reply(outcome='staged', data=data)
                self._wire_current(2)
                self._owner.validate(); self._validate_opening(); self._check('acquiring')
                self._state = 'staged'
                return result
            except Exception: self._abort('publication_native_staging_rejected')

    def retire(self, frame):
        with self._lock:
            try:
                self._check('staged')
                self._state = 'retiring'
                self._wire.accept_retirement(frame)
                self._wire_current(3)
                self._validate_opening(); self._owner.validate()
                self._owner.close()  # Native uncertainty withholds the claim entirely.
                self._check('retiring')
                result = self._wire.acknowledge_retirement()
                self._wire_current(4)
                self._check('retiring')
                self._shutdown()
                self._retired_snapshot_current()
                if self._cancelled: raise NativeAcquisitionError('cancelled_during_cleanup')
                return result
            except Exception: self._abort('publication_native_retirement_rejected')

    def _retired_snapshot_current(self):
        """Checks after ordinary/context cleanup; no permission or result token."""
        self._wire_current(4)
        self._owner.validate_description(); self._validate_opening()
        if (self._owner_changed is not False or self._wire_changed is not False
                or self._owner is not self._issued_owner or type(self._state) is not str or self._state != 'closed'
                or type(self._owner._closed) is not bool or not self._owner._closed
                or self._owner._fd is not None or self._owner._issued_fd is not None
                or self._owner._cleanup_failed is not False
                or type(self._owner._deadline) is not float or self._owner._deadline != self._owner_deadline_snapshot
                or type(self._deadline) is not float or self._deadline != self._adapter_deadline_snapshot
                or monotonic() >= min(self._adapter_deadline_snapshot, self._owner_deadline_snapshot)):
            raise NativeAcquisitionError('changed_during_final_native_cleanup')

    def _shutdown(self):
        # Retire only issued ownership, never a substituted foreign object. Keep
        # terminal evidence of the substitution so cleanup cannot mask it.
        original = getattr(self, '_issued_owner', None)
        if original is not None and self._owner is not original:
            self._owner_changed, self._owner = True, original
        original_wire = getattr(self, '_issued_wire', None)
        if original_wire is not None and self._wire is not original_wire:
            self._wire_changed, self._wire = True, original_wire
        super()._shutdown()
