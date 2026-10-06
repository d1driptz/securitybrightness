"""Inactive native fixture quarantine plus an original live recipient dry run."""
from contextlib import nullcontext
import time
from . import broker_transport as transport
from .broker_publication_host import BrokerPublicationDiscardHost
from .broker_review_host import BrokerReviewHostError
from .broker_live_channel_check import LiveChannelPublicationCheck, LiveChannelCheckError
from .broker_recipient_channel import RecipientChannelShutdownStatus
from .broker_process import BrokerProcessError


class BrokerLiveChannelPublicationHost(BrokerPublicationDiscardHost):
    """Two sequential fixed children under one original admission/authority owner.

    The fixture child has retired/EOF/zero-exit/joined before recipient launch.
    The same claimed logical recipient and quarantine are retained across proof
    and the final dry run, which discards all bytes while the peer is still live.
    No caller callback/profile/endpoint or delivery operation is accepted.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._channel_check = self._issued_channel_check = None

    def _check_final_publication(self, lifecycle, app, credential, proposal, descriptor):
        self._check()
        if self._channel_check is not None or self._issued_channel_check is not None:
            raise BrokerReviewHostError('live_channel_already_attempted')
        check = self._channel_check = self._issued_channel_check = LiveChannelPublicationCheck(
            lifecycle, timeout=min(5, self._deadline-time.monotonic()))
        try:
            return check.run(app, credential, proposal, descriptor)
        except BaseException:
            try:
                status = check.shutdown_status()
                confirmed = type(status) is RecipientChannelShutdownStatus and status.cleanup_confirmed is True
            except BaseException:
                confirmed = False
            if not confirmed:
                # The original host still owns admission. Never release it on
                # uncertain recipient native cleanup, even if source cleanup works.
                raise BrokerProcessError('process_cleanup_failed') from None
            raise

    def _final_check_guard(self):
        check = self._channel_check
        if check is None and self._issued_channel_check is None: return nullcontext()
        if type(check) is not LiveChannelPublicationCheck or check is not self._issued_channel_check:
            raise BrokerReviewHostError('changed_live_channel_owner')
        return check._lock  # Acquired before source locks; no lock-order inversion.

    def _post_check_evidence(self):
        check = self._channel_check
        if check is None and self._issued_channel_check is None: return
        if type(check) is not LiveChannelPublicationCheck or check is not self._issued_channel_check:
            raise BrokerReviewHostError('changed_live_channel_owner')
        try:
            check.retired_check()
        except BrokerProcessError:
            transport._slot.acquire(blocking=False)  # Poison free admission only.
            self._cleanup_confirmed = False
            raise BrokerReviewHostError('live_channel_cleanup_uncertain') from None
        except LiveChannelCheckError:
            raise BrokerReviewHostError('changed_live_channel_evidence') from None

    def close(self):
        # Preserve original host cancellation, and signal the exact helper
        # without closing its child from a second thread. The worker joins it.
        super().close()
        check = getattr(self, '_issued_channel_check', None)
        if type(check) is LiveChannelPublicationCheck: check.close()
