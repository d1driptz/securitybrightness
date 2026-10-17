"""Inactive, disjoint bounded-wait fixture transcripts; never permission.

The opening and acquisition profiles deliberately authenticate different domains
from each other and from every existing live, desktop and publication profile.
Only acquisition creates the original at-most-five-second quarantine lifetime.
"""
import hashlib
import hmac

from .broker_live_protocol import LiveMetadataExchange
from .broker_publication_protocol import PublicationCheckExchange


class _WaitOpeningExchange(LiveMetadataExchange):
    def _mac(self, direction, body):
        domain = b'SecurityBrightness.bounded-wait-fixture-opening.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)


class _WaitAcquisitionExchange(PublicationCheckExchange):
    def _mac(self, direction, body):
        domain = b'SecurityBrightness.bounded-wait-fixture-acquisition.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)
