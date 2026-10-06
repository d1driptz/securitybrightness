"""Inactive fixed fixture + private native dry-commit composition; zero delivery."""
from contextlib import nullcontext
import time
from . import broker_transport as transport
from .broker_publication_host import BrokerPublicationDiscardHost
from .broker_review_host import BrokerReviewHostError
from .broker_native_commit_check import NativePublicationCommitCheck
from .broker_live_channel_check import LiveChannelCheckError
from .broker_recipient_channel import RecipientChannelShutdownStatus
from .broker_process import BrokerProcessError


class BrokerNativePublicationCommitHost(BrokerPublicationDiscardHost):
    """Two sequential fixed children under one original admission owner.

    The fixture child joins before the commit peer launches. Actual dry-commit
    messages bind the existing recipient, quarantine and one-use authority. All
    bytes are discarded; joined peer receipts remain metadata only. No selectable
    endpoint/profile, file operation, byte delivery or active route is added.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._channel_check = self._issued_channel_check = None

    def _check(self):
        super()._check()
        check, issued = getattr(self, '_channel_check', None), getattr(self, '_issued_channel_check', None)
        if check is None and issued is None: return
        if type(check) is not NativePublicationCommitCheck or check is not issued:
            raise BrokerReviewHostError('changed_native_commit_owner')

    def _check_final_publication(self, lifecycle, app, credential, proposal, descriptor):
        self._check()
        if self._channel_check is not None or self._issued_channel_check is not None:
            raise BrokerReviewHostError('native_commit_already_attempted')
        check = self._channel_check = self._issued_channel_check = NativePublicationCommitCheck(
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
                raise BrokerProcessError('process_cleanup_failed') from None
            raise

    def _final_check_guard(self):
        check = self._channel_check
        if check is None and self._issued_channel_check is None: return nullcontext()
        if type(check) is not NativePublicationCommitCheck or check is not self._issued_channel_check:
            raise BrokerReviewHostError('changed_native_commit_owner')
        return check._lock

    def _post_check_evidence(self):
        check = self._channel_check
        if check is None and self._issued_channel_check is None: return
        if type(check) is not NativePublicationCommitCheck or check is not self._issued_channel_check:
            raise BrokerReviewHostError('changed_native_commit_owner')
        try:
            check.retired_check()
            if (self._channel_check is not check or self._issued_channel_check is not check
                    or type(check) is not NativePublicationCommitCheck):
                raise BrokerReviewHostError('changed_native_commit_owner')
        except BrokerProcessError:
            transport._slot.acquire(blocking=False)
            self._cleanup_confirmed = False
            raise BrokerReviewHostError('native_commit_cleanup_uncertain') from None
        except LiveChannelCheckError:
            raise BrokerReviewHostError('changed_native_commit_evidence') from None

    def close(self):
        super().close()
        check = getattr(self, '_issued_channel_check', None)
        if type(check) is NativePublicationCommitCheck: check.close()
