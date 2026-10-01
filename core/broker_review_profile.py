"""Private metadata-only human-wait profile; distinct authenticated domain."""
import hashlib
import hmac
from .broker_live_protocol import LiveMetadataExchange


class _ReviewWaitExchange(LiveMetadataExchange):
    def _mac(self, direction, body):
        domain = b'SecurityBrightness.review-wait-metadata.v1\0'
        key = hmac.digest(self._key, domain+direction.encode('ascii'), hashlib.sha256)
        return hmac.digest(key, domain+body, hashlib.sha256)
