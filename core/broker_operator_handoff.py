"""Inactive trusted-local-UI handoff; no network approval endpoint or person auth.

The host distributes worker and operator ports separately. Responses record
review evidence only. No /check, broker IPC, content access or grant integration.
"""
from dataclasses import dataclass, asdict, field
import math
import secrets
import re
import threading
from time import monotonic
from .broker_pending_review import PendingBrokerReview, PendingRequest
from .broker_protocol import _canonical


class BrokerOperatorError(ValueError):
    pass


@dataclass(frozen=True)
class BrokerOperatorPrompt:
    review_id: str
    canonical_display: bytes = field(repr=False)
    def __bool__(self): raise TypeError('An operator prompt is not permission')


@dataclass(frozen=True)
class OperatorResponseQueued:
    meaning: str = 'response queued; freshness not yet confirmed'
    def __bool__(self): raise TypeError('A queued response is not permission')


class _WorkerPort:
    def __init__(self, channel): self._channel=channel
    def request_review(self, request): return self._channel._request(request)


class _TrustedOperatorPort:
    def __init__(self, channel): self._channel=channel
    def pending(self): return self._channel._pending()
    def respond(self, prompt, text): return self._channel._respond(prompt,text)
    def cancel(self): self._channel.close()


class BrokerOperatorHandoff:
    """Single prompt, fixed lifetime <=30s, never reset or reused.

    Trusted bootstrap/UI possession of the operator port is the boundary; Python
    object privacy is not protection against hostile code in the same process.
    A queued answer is revalidated by PendingBrokerReview before evidence returns.
    Timer expiry closes the model even after response, unless already consumed.
    """
    def __init__(self, model, *, timeout=30):
        if type(model) is not PendingBrokerReview:
            raise TypeError('expected pending review coordinator')
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=30:
            raise ValueError('invalid_operator_timeout')
        self._model,self._timeout=model,timeout
        self._condition=threading.Condition()
        self._started=self._closed=self._finished=False
        self._prompt=self._answer=self._timer=None
        self._cleanup_failed=False
        self.worker=_WorkerPort(self)
        self.operator=_TrustedOperatorPort(self)

    def _current(self):
        if self._closed or self._cleanup_failed or monotonic()>=self._deadline:
            raise BrokerOperatorError('operator_review_unavailable')

    def _request(self, request):
        with self._condition:
            try:
                if self._started or self._closed or type(request) is not PendingRequest:
                    raise BrokerOperatorError('operator_review_unavailable')
                self._started=True
                self._deadline=monotonic()+self._timeout
                self._display=self._model.operator.display(request)
                self._snapshot=_canonical(asdict(self._display))
                if len(self._snapshot)>16384:
                    raise BrokerOperatorError("display_limit")
                self._review_id=secrets.token_hex(32)
                if type(self._review_id) is not str or re.fullmatch('[0-9a-f]{64}',self._review_id) is None:
                    raise BrokerOperatorError('invalid_review_identity')
                self._prompt=BrokerOperatorPrompt(self._review_id,self._snapshot)
                self._current()
                self._timer=threading.Timer(max(0,self._deadline-monotonic()),self.close)
                self._timer.daemon=True
                self._timer.start()
                self._condition.notify_all()
                while self._answer is None:
                    self._current()
                    self._condition.wait(max(0,self._deadline-monotonic()))
                self._current()
                result=self._model.operator.record(self._display,self._answer)
                self._current()
                self._finished=True
                # Timer remains armed: leaving evidence unconsumed cannot retain
                # a local fixture indefinitely, or extend the review deadline.
                return result
            except Exception:
                self.close()
                raise BrokerOperatorError('operator_review_unavailable') from None

    def _pending(self):
        with self._condition:
            if not self._started or self._closed or self._finished or self._answer is not None:
                return ()
            try:
                self._current()
                if self._prompt.review_id!=self._review_id or self._prompt.canonical_display!=self._snapshot:
                    raise BrokerOperatorError('changed_prompt')
                return (self._prompt,)
            except Exception:
                self.close()
                return ()

    def _respond(self, prompt, text):
        with self._condition:
            try:
                if not self._started: raise BrokerOperatorError('no_prompt')
                self._current()
                if (self._finished or self._answer is not None or type(prompt) is not BrokerOperatorPrompt
                        or prompt is not self._prompt or prompt.review_id!=self._review_id
                        or type(prompt.canonical_display) is not bytes or prompt.canonical_display!=self._snapshot
                        or type(text) is not str or text not in {'ALLOW ONCE','DENY'}):
                    raise BrokerOperatorError('invalid_operator_response')
                self._answer='allow_once' if text=='ALLOW ONCE' else 'deny'
                self._condition.notify_all()
                return OperatorResponseQueued()
            except Exception:
                self.close()
                raise BrokerOperatorError('operator_response_rejected') from None

    def close(self):
        with self._condition:
            self._closed=True
            self._answer=None
            if self._timer is not None: self._timer.cancel()
            try: self._model.close()
            except Exception: self._cleanup_failed=True
            finally: self._condition.notify_all()

    def __enter__(self): return self
    def __exit__(self,*_): self.close()
