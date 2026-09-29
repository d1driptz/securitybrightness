"""Private bootstrap framing; possession is not authority or code attestation."""
import hmac
import hashlib

MAGIC = b'SBBoot01'
READY = b'SBReady1'
BOOT_SIZE = 72
READY_SIZE = 76


def ready(key, session, pid):
    body = READY + pid.to_bytes(4, 'big') + session
    return body + hmac.digest(key, b'SB-private-startup-v1\0' + body, hashlib.sha256)
