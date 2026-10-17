"""Inactive three-child generated-fixture composition; metadata/discard only.

No existing host, protected reader, desktop walkthrough or route selects this
diagnostic. Five seconds total, automated decisions in tests, no payload delivery.
"""
from collections import namedtuple
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import hmac
import math
import secrets
from threading import Condition, Event, RLock, current_thread
from time import monotonic, sleep

from .broker_acquisition_draft import AcquisitionDraft
from .broker_live_review import LiveBrokerReview
from .broker_live_protocol import LiveMetadataExchange
from .broker_pending_review import PendingDisplay
from .broker_protocol import _canonical
from .broker_publication_lifecycle import LivePublicationDraft
from .broker_publication_protocol import PublicationCheckExchange
from .broker_publication_recipient import LogicalPublicationRecipient
from .broker_review_host import BrokerReviewHost, BrokerReviewHostError, BrokerShutdownStatus
from .broker_source_admission import _SourceAdmissionCustody, _Source, _Review, _Wire, _Fixture
from .broker_source_fixture_stage import _SourceFixtureStage, _display_snapshot
from .broker_source_native_association import SourceNativeAssociationEvidence, _facts

_RLOCK = type(RLock())
_Origin = namedtuple('_Origin', 'host registry ledger registry_lock ledger_lock condition condition_lock cancel worker operator timeout started finished failed')
_Run = namedtuple('_Run', 'host custody custody_origin thread ident deadline')
_Live = namedtuple('_Live', 'started finished cleanup thread ident deadline custody custody_origin model recipient lifecycle stage stage_origin display answer result snapshot')


@dataclass(frozen=True)
class RetiredSourceFixtureDenial:
    canonical_display: bytes = field(repr=False)
    decision: str = field(default='deny', init=False)
    released_bytes: int = field(default=0, init=False)
    meaning: str = field(default='Inactive generated-fixture denial; no operation or later authority.', init=False)
    def __bool__(self): raise TypeError('A fixture denial record is not permission')


def _result_snapshot(result):
    if type(result) is SourceNativeAssociationEvidence: return _facts(result)
    if type(result) is RetiredSourceFixtureDenial:
        values = (result.canonical_display, result.decision, result.released_bytes, result.meaning)
        if (type(values[0]) is not bytes or not 1 <= len(values[0]) <= 65536
                or type(values[1]) is not str or values[1] != 'deny'
                or type(values[2]) is not int or values[2] != 0
                or type(values[3]) is not str or len(values[3]) > 256):
            raise BrokerReviewHostError('invalid_fixture_denial')
        return tuple((type(value), value) for value in values)
    raise BrokerReviewHostError('invalid_fixture_result')


class BrokerSourceFixtureHost(BrokerReviewHost):
    """Fixed three-child discard diagnostic under one original admission owner.

    Operator possession is trusted-local bootstrap, not human authentication.
    Only the original worker disposes native resources; cancellation signals.
    The first fixture child remains independently checked through final release.
    No path, executable, key, callback, endpoint or profile selector is accepted.
    """
    def __init__(self, registry, ledger, *, timeout=5):
        if type(self) is not BrokerSourceFixtureHost:
            raise TypeError('expected exact fixed fixture host')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 5:
            raise ValueError('invalid_fixture_host_lifetime')
        super().__init__(registry, ledger, timeout=timeout)
        origin = _Origin(self, registry, ledger, registry._lock, ledger._lock,
            self._condition, self._condition._lock, self._cancel, self.worker, self.operator,
            (type(timeout), timeout), Event(), Event(), Event())
        self._origin = self._issued_origin = self._recovery_origin = origin
        self._run_owner = self._issued_run_owner = self._recovery_run_owner = None
        self._live = self._issued_live = self._recovery_live = _Live(False, False, False,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None)
        self._custody = self._issued_custody = None
        self._model = self._issued_model = self._recipient = self._issued_recipient = None
        self._lifecycle = self._issued_lifecycle = self._fixture_stage = self._issued_fixture_stage = None

    @staticmethod
    def _recover(values, kind):
        for value in values:
            if type(value) is kind and sum(item is value for item in values) >= 2: return value
        raise BrokerReviewHostError('uncertain_fixture_host_owner')

    def _original(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_origin', '_issued_origin', '_recovery_origin')), _Origin)

    def _status(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_live', '_issued_live', '_recovery_live')), _Live)

    def _save(self, **changes):
        live = self._status()._replace(**changes)
        self._live = self._issued_live = self._recovery_live = live
        self._started, self._finished, self._cleanup_confirmed = live.started, live.finished, live.cleanup
        self._display, self._answer = live.display, live.answer
        for name in ('custody', 'model', 'recipient', 'lifecycle'):
            setattr(self, '_'+name, getattr(live, name)); setattr(self, '_issued_'+name, getattr(live, name))
        self._fixture_stage = self._issued_fixture_stage = live.stage
        return live

    def _identity(self, *, active=True, thread=False):
        origin, live = self._original(), self._status()
        if (origin.host is not self
                or any(getattr(self, name, None) is not origin for name in ('_origin', '_issued_origin', '_recovery_origin'))
                or any(getattr(self, name, None) is not live for name in ('_live', '_issued_live', '_recovery_live'))
                or self._registry is not origin.registry or self._ledger is not origin.ledger
                or origin.registry._lock is not origin.registry_lock or origin.ledger._lock is not origin.ledger_lock
                or self._condition is not origin.condition or self._cancel is not origin.cancel
                or origin.condition._lock is not origin.condition_lock
                or self.worker is not origin.worker or self.operator is not origin.operator
                or origin.worker._host is not self or origin.operator._host is not self
                or (type(self._timeout), self._timeout) != origin.timeout
                or any(type(flag) is not bool for flag in live[:3])
                or self._started is not live.started or self._finished is not live.finished
                or self._cleanup_confirmed is not live.cleanup or self._display is not live.display
                or live.started is not origin.started.is_set() or live.finished is not origin.finished.is_set()
                or self._answer is not live.answer
                or any(getattr(self, prefix+name, None) is not getattr(live, name)
                    for name in ('custody', 'model', 'recipient', 'lifecycle') for prefix in ('_', '_issued_'))
                or self._fixture_stage is not live.stage or self._issued_fixture_stage is not live.stage):
            raise BrokerReviewHostError('changed_fixture_host_owner')
        if live.started:
            run = self._recover(tuple(getattr(self, name, None) for name in
                ('_run_owner', '_issued_run_owner', '_recovery_run_owner')), _Run)
            if (type(live.deadline) is not float or type(self._deadline) is not float or self._deadline != live.deadline
                    or type(live.custody) is not _SourceAdmissionCustody or live.custody._original() is not live.custody_origin
                    or live.deadline != live.custody_origin.deadline
                    or run.host is not self or run.custody is not live.custody or run.custody_origin is not live.custody_origin
                    or run.thread is not live.thread or run.ident != live.ident or run.deadline != live.deadline
                    or any(getattr(self, name, None) is not run for name in ('_run_owner', '_issued_run_owner', '_recovery_run_owner'))
                    or thread and (current_thread() is not live.thread or current_thread().ident != live.ident)):
                raise BrokerReviewHostError('changed_fixture_worker_owner')
        if live.stage is not None and (type(live.stage) is not _SourceFixtureStage
                or _SourceFixtureStage._original(live.stage) is not live.stage_origin
                or live.custody._fixture_stage is not live.stage):
            raise BrokerReviewHostError('changed_fixture_stage_owner')
        if live.display is not None and (type(live.display) is not PendingDisplay
                or _display_snapshot(live.display) != self._snapshot):
            raise BrokerReviewHostError('changed_fixture_display')
        if live.result is not None and _result_snapshot(live.result) != live.snapshot:
            raise BrokerReviewHostError('changed_fixture_result')
        if active and (origin.cancel.is_set() or origin.failed.is_set() or live.started and monotonic() >= live.deadline):
            raise BrokerReviewHostError('expired_or_cancelled_fixture_host')
        return live

    def _check(self):
        self._identity()

    @contextmanager
    def _condition_guard(self):
        origin = self._original()
        if (origin.host is not self or origin.condition._lock is not origin.condition_lock
                or type(origin.condition_lock) is not _RLOCK):
            raise BrokerReviewHostError('changed_fixture_control')
        while not origin.condition_lock.acquire(blocking=False):
            if not origin.started.is_set():
                raise BrokerReviewHostError('busy_fixture_control')
            run = self._recover(tuple(getattr(self, name, None) for name in
                ('_run_owner', '_issued_run_owner', '_recovery_run_owner')), _Run)
            if run.host is not self or current_thread() is not run.thread:
                raise BrokerReviewHostError('busy_fixture_control')
            source = run.custody._archive('source', _Source)
            fixture = run.custody._archive('fixture', _Fixture)
            wire = run.custody._archive('wire', _Wire)
            extra = ()
            if fixture is not None:
                native = fixture.stage._native_original()
                extra = (fixture.origin.lock,)+(() if native is None else (native.lock,))
            if (origin.cancel.is_set() or monotonic() >= run.deadline
                    or source is not None and any(lock._is_owned() for lock in source.locks)
                    or run.custody_origin.lock._is_owned()
                    or wire is not None and wire.lock._is_owned()
                    or any(type(lock) is not _RLOCK or lock._is_owned() for lock in extra)):
                raise BrokerReviewHostError('busy_fixture_control')
            sleep(.001)  # Private control only, outside authority, unchanged deadline.
        try: yield origin
        finally: origin.condition_lock.release()

    def _pending(self):
        origin = self._original()
        if origin.host is not self: return ()
        try:
            with self._condition_guard():
                live = self._identity()
                if not live.started or live.finished or live.display is None or live.answer is not None: return ()
                return (live.display,)
        except Exception as error:
            if str(error) != 'busy_fixture_control': self.close()
            return ()

    def _respond(self, display, answer):
        origin = self._original()
        if origin.host is not self: raise BrokerReviewHostError('foreign_fixture_host')
        try:
            with self._condition_guard():
                live = self._identity()
                if (not live.started or live.finished or live.answer is not None or display is not live.display
                        or type(display) is not PendingDisplay or _display_snapshot(display) != self._snapshot
                        or type(answer) is not str or answer not in ('ALLOW ONCE', 'DENY')):
                    raise BrokerReviewHostError('invalid_fixture_response')
                self._save(answer=answer)
                from .broker_operator_handoff import OperatorResponseQueued
                return OperatorResponseQueued()
        except Exception:
            self.close(); raise BrokerReviewHostError('fixture_response_rejected') from None

    def close(self):
        origin = self._original()
        if origin.host is not self: raise BrokerReviewHostError('foreign_fixture_host')
        origin.cancel.set()
        if origin.started.is_set():
            run = self._recover(tuple(getattr(self, name, None) for name in
                ('_run_owner', '_issued_run_owner', '_recovery_run_owner')), _Run)
            if run.host is self: run.custody_origin.cancel.set()

    def _shutdown_status(self):
        origin = self._original()
        try:
            with self._condition_guard():
                live = self._identity(active=False)
                if not live.finished: return None
                if live.cleanup and live.custody is not None:
                    with live.custody._control(), live.custody._guards(): live.custody._cleanup_current()
                return BrokerShutdownStatus(live.cleanup)
        except Exception: return BrokerShutdownStatus(False)

    def _dispose_source(self, custody, stage):
        """Retire captured originals only. Restoring disposal links grants nothing."""
        def recover(name, kind):
            return custody._recover(tuple(getattr(custody, prefix+name, None) for prefix in
                ('_', '_issued_', '_recovery_')), kind, optional=True)
        source, review, wire = recover('source', _Source), recover('review', _Review), recover('wire', _Wire)
        if source is None and type(stage) is _SourceFixtureStage:
            source = _SourceFixtureStage._original(stage).source
        if type(source) is not _Source:
            custody._poison(); raise BrokerReviewHostError('uncertain_original_source_disposal')
        changed = any(getattr(obj, name, None) is not value for obj, name, value in source.fields)
        try: custody._identity(active=False)
        except BaseException: changed = True
        if wire is None and source.source._wire is not None: changed = True
        if review is None and source.review._timer is not None: changed = True
        if changed: custody._poison()
        with ExitStack() as stack:
            locks = source.locks+(() if wire is None else (wire.lock,))
            for lock in locks:
                if type(lock) is not _RLOCK or not lock.acquire(blocking=False):
                    custody._poison(); raise BrokerReviewHostError('busy_original_source_disposal')
                stack.callback(lock.release)
            # Never repair registry/ledger shared fields. Local graph links are
            # restored solely for disposal after an irreversible failure latch.
            for obj, name, value in source.fields:
                if obj is not source.registry and obj is not source.ledger:
                    if getattr(obj, name, None) is not value: setattr(obj, name, value)
            try:
                if wire is not None:
                    original = wire.wire
                    if (source.source._wire is not original or original._lock is not wire.lock
                            or original._timer is not wire.timer or original._timer_snapshot is not wire.timer
                            or wire.timer.finished is not wire.finished): custody._poison()
                    source.source._wire, source.source._owned_buffer = original, wire.buffer
                    original._lock, original._buffer, original._issued_buffer = wire.lock, wire.buffer, wire.buffer
                    original._timer = original._timer_snapshot = wire.timer
                    wire.timer.finished = wire.finished
                    PublicationCheckExchange.close(original)
                elif source.source._wire is not None:
                    # Untracked creation cannot certify cleanup; never dispatch
                    # an unknown codec's methods during best-effort disposal.
                    source.source._wire = None
            finally:
                source.source._state, source.source._closing = 'closed', False
                source.acquisition._closed, source.acquisition._issued = True, None
                source.review._state = 'closed'
                LiveMetadataExchange.close(source.review._exchange)
                if review is not None:
                    if source.review._timer is not review.timer or review.timer.finished is not review.finished:
                        custody._poison()
                    source.review._timer, review.timer.finished = review.timer, review.finished
                    source.review._ticket = review.ticket
                    Event.set(review.finished)
                    # Remove only the originally captured review maps and ID;
                    # a substituted manager or shared lock is never invoked.
                    for obj, name, value in source.fields:
                        if (obj is source.ledger and name == '_reviews'
                                or obj is source.review._reviews and name == '_pending'):
                            if type(value) is not dict:
                                custody._poison(); raise BrokerReviewHostError('changed_original_review_map')
                            dict.pop(value, review.draft_id, None)
                else:
                    source.review._timer = None
                source.recipient._terminal, source.recipient._state, source.recipient._claim = True, 'closed', None
                if (source.recipient._timer is not source.recipient_timer
                        or source.recipient_timer.finished is not source.recipient_finished): custody._poison()
                source.recipient._timer, source.recipient_timer.finished = source.recipient_timer, source.recipient_finished
                Event.set(source.recipient_finished)
                custody._wipe_original()

    def _run(self, app, credential, proposal, draft_id, revision):
        origin = self._original()
        if origin.host is not self: raise BrokerReviewHostError('foreign_fixture_host')
        with self._condition_guard():
            live = self._identity()
            if live.started:
                self.close(); raise BrokerReviewHostError('fixture_host_attempt_spent')
            custody = _SourceAdmissionCustody(timeout=self._timeout)
            self._deadline = custody._deadline
            run = _Run(self, custody, custody._original(), current_thread(), current_thread().ident, self._deadline)
            self._run_owner = self._issued_run_owner = self._recovery_run_owner = run
            origin.started.set()
            self._save(started=True, thread=current_thread(), ident=current_thread().ident,
                deadline=self._deadline, custody=custody, custody_origin=custody._original())
        stage = model = recipient = lifecycle = result = None
        cleanup = False
        try:
            self._identity(thread=True)
            custody.acquire()
            self._check()
            key, session = secrets.token_bytes(32), secrets.token_bytes(32)
            if (type(key) is not bytes or type(session) is not bytes or len(key) != 32
                    or len(session) != 32 or hmac.compare_digest(key, session)):
                raise BrokerReviewHostError('invalid_fixture_bootstrap')
            model = LiveBrokerReview(origin.registry, origin.ledger, key=key, session=session, timeout=self._timeout)
            recipient = LogicalPublicationRecipient(app, timeout=self._timeout)
            lifecycle = LivePublicationDraft(AcquisitionDraft(model), recipient)
            custody.bind_source(lifecycle)
            with self._condition_guard(): self._save(model=model, recipient=recipient, lifecycle=lifecycle)
            stage = _SourceFixtureStage(custody)
            with self._condition_guard(): self._save(stage=stage, stage_origin=stage._original())
            first = custody.begin_review(app, credential, proposal, draft_id, revision)
            self._check()
            display = stage.open(first)
            with self._condition_guard():
                self._identity(thread=True)
                self._snapshot = _display_snapshot(display)
                self._save(display=display)
            while True:
                with self._condition_guard():
                    live = self._identity(thread=True)
                    answer = live.answer
                if answer is not None: break
                stage._native_current()
                sleep(.005)  # No authority/control guard crosses this bounded wait.
            model.operator.record(display, answer)
            if answer == 'DENY':
                result = RetiredSourceFixtureDenial(model._facts_snapshot)
                stage.close()
                custody.abort()
            else:
                stage.stage(app, credential, proposal)
                stage.retire()
                self._check()
                result = custody.finish(app, credential, proposal, recipient._issued)
            result_snapshot = _result_snapshot(result)
        except BaseException:
            result = None
        finally:
            try:
                try:
                    if stage is not None: _SourceFixtureStage.close(stage)
                finally:
                    # Known original logical owners retire even when native
                    # cleanup is uncertain. This never clears admission poison.
                    if lifecycle is not None and custody._original().source_seen.is_set():
                        self._dispose_source(custody, stage)
                    elif lifecycle is not None: LivePublicationDraft._shutdown(lifecycle)
                    else:
                        try:
                            if model is not None: LiveBrokerReview.close(model)
                        finally:
                            if recipient is not None: LogicalPublicationRecipient.close(recipient)
                history = custody._status()
                if history.acquired and not history.released and not history.attempted and not history.poisoned:
                    custody.abort()
                history = custody._status()
                if history.released:
                    with custody._control(), custody._guards(): custody._cleanup_current()
                    cleanup = True
                elif (not history.acquired and model is None and recipient is None
                        and lifecycle is None and stage is None and not custody._original().source_seen.is_set()
                        and not custody._original().fixture_seen.is_set()):
                    cleanup = True  # Independently no model/native creation accepted.
                else:
                    custody._wipe_original()
            except BaseException:
                result = None; cleanup = False
                custody._wipe_original()
            finally:
                with self._condition_guard():
                    try: self._identity(active=False, thread=True)
                    except BaseException:
                        origin.failed.set(); result = None; cleanup = False
                    origin.finished.set()
                    self._save(finished=True, cleanup=cleanup, display=None, answer=None,
                        result=result, snapshot=result_snapshot if result is not None else None)
        if result is None or not cleanup: raise BrokerReviewHostError('fixture_session_rejected') from None
        try:
            with self._condition_guard():
                live = self._identity(thread=True)
                with custody._control(), custody._guards():
                    custody._cleanup_current()
                    if type(result) is SourceNativeAssociationEvidence:
                        custody._status().gate._final_current(result)
                    if live.result is not result or _result_snapshot(result) != result_snapshot:
                        raise BrokerReviewHostError('changed_fixture_final_result')
                self._identity(thread=True)
                return result
        except BaseException:
            custody._wipe_original()
            raise BrokerReviewHostError('fixture_retirement_rejected') from None
