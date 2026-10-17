"""Inactive bounded worker scheduling; no review, permission, or native access.

The human-wait budget and subsequent acquisition budget are deliberately separate.
Neither completing a phase nor possessing its absolute deadline authorizes an
operation. Native ownership, current authority, and exact review remain separate.
"""
from collections import deque, namedtuple
from contextlib import contextmanager
import math
from threading import Event, RLock, current_thread
from time import monotonic


_RLOCK, _EVENT = type(RLock()), type(Event())
_Origin = namedtuple('_Origin', 'owner thread ident lock cancel created deadline_wait '
    'deadline_total entered terminal failed clock')
_Acquisition = namedtuple('_Acquisition', 'owner started deadline')
_History = namedtuple('_History', 'phase last_seen acquisition')


class WaitPhaseError(RuntimeError):
    pass


class _WaitAcquisitionPhases:
    """One original worker, <=30s waiting then <=5s acquisition; no renewal.

    cancel/close only signal original events, including across threads. They do
    not wait for the worker, clean native resources, or certify their retirement.
    Every check must run on the original worker with its original private lock.
    There are no timeout, clock, identity, path, callback, or authority selectors.
    """
    def __init__(self):
        if type(self) is not _WaitAcquisitionPhases:
            raise TypeError('expected exact bounded phase owner')
        created = self._finite(monotonic())
        wait, total = created+30.0, created+35.0
        if not math.isfinite(total) or not created < wait < total:
            raise WaitPhaseError('invalid_phase_clock')
        origin = _Origin(self, current_thread(), current_thread().ident, RLock(),
            Event(), created, wait, total, Event(), Event(), Event(), deque((created,), maxlen=1))
        self._origin = self._issued_origin = self._recovery_origin = origin
        self._retained_origin = origin
        self._lock, self._cancel = origin.lock, origin.cancel
        self._created, self._deadline_wait, self._deadline_total = created, wait, total
        self._acquisition = self._issued_acquisition = self._recovery_acquisition = None
        self._save('waiting', created, None)

    @staticmethod
    def _finite(value):
        if type(value) is not float or not math.isfinite(value):
            raise WaitPhaseError('invalid_phase_clock')
        return value

    @staticmethod
    def _recover(values, kind):
        for value in values:
            if type(value) is kind and sum(item is value for item in values) >= 2:
                return value
        raise WaitPhaseError('uncertain_phase_archive')

    def _original(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_origin', '_issued_origin', '_recovery_origin')), _Origin)

    def _history(self):
        return self._recover(tuple(getattr(self, name, None) for name in
            ('_state', '_issued_state', '_recovery_state')), _History)

    def _save(self, phase, now, acquisition):
        state = _History(phase, now, acquisition)
        self._state = self._issued_state = self._recovery_state = state
        self._original().clock[0] = now
        return state

    def _fail(self):
        try:
            origin = self._disposal_owner()
            if origin.owner is self:
                origin.failed.set(); origin.terminal.set(); origin.cancel.set()
        except Exception:
            pass  # Missing ownership cannot select another component to cancel.

    def _disposal_owner(self):
        origin = getattr(self, '_retained_origin', None)
        if type(origin) is not _Origin or origin.owner is not self:
            origin = self._original()
        if (origin.owner is not self or any(type(value) is not _EVENT
                for value in (origin.cancel, origin.terminal, origin.failed))):
            raise WaitPhaseError('uncertain_phase_cancellation')
        return origin

    @contextmanager
    def _guard(self):
        try:
            origin = self._original()
        except BaseException:
            self._fail(); raise
        if origin.owner is not self or type(origin.lock) is not _RLOCK:
            self._fail()
            raise WaitPhaseError('foreign_phase_owner')
        if not origin.lock.acquire(blocking=False):
            self._fail(); raise WaitPhaseError('busy_phase_owner')
        try:
            yield origin
        except BaseException:
            self._fail(); raise
        finally:
            origin.lock.release()

    def _identity(self, expected):
        origin, state = self._original(), self._history()
        if (origin.owner is not self
                or self._retained_origin is not origin
                or any(getattr(self, name, None) is not origin for name in
                    ('_origin', '_issued_origin', '_recovery_origin'))
                or any(getattr(self, name, None) is not state for name in
                    ('_state', '_issued_state', '_recovery_state'))
                or current_thread() is not origin.thread or current_thread().ident != origin.ident
                or self._lock is not origin.lock or self._cancel is not origin.cancel
                or any(type(value) is not _EVENT for value in
                    (origin.cancel, origin.entered, origin.terminal, origin.failed))
                or any(type(value) is not float or not math.isfinite(value) for value in
                    (origin.created, origin.deadline_wait, origin.deadline_total,
                     self._created, self._deadline_wait, self._deadline_total, state.last_seen))
                or self._created != origin.created or self._deadline_wait != origin.deadline_wait
                or self._deadline_total != origin.deadline_total
                or origin.deadline_wait != origin.created+30.0
                or origin.deadline_total != origin.created+35.0
                or type(origin.clock) is not deque or origin.clock.maxlen != 1
                or len(origin.clock) != 1 or type(origin.clock[0]) is not float
                or state.last_seen != origin.clock[0] or state.last_seen < origin.created
                or type(state.phase) is not str or state.phase != expected
                or origin.cancel.is_set() or origin.terminal.is_set() or origin.failed.is_set()):
            raise WaitPhaseError('unavailable_phase_owner')
        acquisitions = tuple(getattr(self, name, None) for name in
            ('_acquisition', '_issued_acquisition', '_recovery_acquisition'))
        if expected == 'waiting':
            if origin.entered.is_set() or state.acquisition is not None or any(item is not None for item in acquisitions):
                raise WaitPhaseError('rolled_back_phase_history')
        elif expected == 'acquisition':
            value = self._recover(acquisitions, _Acquisition)
            if (not origin.entered.is_set() or any(item is not value for item in acquisitions)
                    or state.acquisition is not value or value.owner is not self
                    or type(value.started) is not float or not math.isfinite(value.started)
                    or not origin.created <= value.started < origin.deadline_wait
                    or type(value.deadline) is not float or not math.isfinite(value.deadline)
                    or value.deadline != min(value.started+5.0, origin.deadline_total)
                    or not value.started < value.deadline <= origin.deadline_total
                    or state.last_seen < value.started):
                raise WaitPhaseError('changed_acquisition_phase')
        else:
            raise WaitPhaseError('invalid_phase')
        return origin, state

    def _now(self, origin, state, deadline):
        now = self._finite(monotonic())
        if now < state.last_seen or now >= deadline:
            raise WaitPhaseError('expired_or_regressed_phase')
        self._save(state.phase, now, state.acquisition)
        return now

    def check_wait(self):
        with self._guard():
            origin, state = self._identity('waiting')
            self._now(origin, state, origin.deadline_wait)
            self._identity('waiting')
            return origin.deadline_wait

    def enter_acquisition(self):
        with self._guard():
            origin, state = self._identity('waiting')
            now = self._now(origin, state, origin.deadline_wait)
            deadline = min(now+5.0, origin.deadline_total)
            if not math.isfinite(deadline) or not now < deadline:
                raise WaitPhaseError('invalid_acquisition_clock')
            value = _Acquisition(self, now, deadline)
            origin.entered.set()
            self._acquisition = self._issued_acquisition = self._recovery_acquisition = value
            self._save('acquisition', now, value)
            self._identity('acquisition')
            return deadline

    def check_acquisition(self):
        with self._guard():
            origin, state = self._identity('acquisition')
            self._now(origin, state, state.acquisition.deadline)
            self._identity('acquisition')
            return state.acquisition.deadline

    def close(self):
        origin = self._disposal_owner()
        origin.cancel.set(); origin.terminal.set()

    cancel = close

    def __bool__(self):
        raise TypeError('Scheduling phases are not permission')
