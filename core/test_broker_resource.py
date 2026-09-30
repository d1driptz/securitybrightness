"""Only generated fixtures; no personal file operations or broker activation."""
from dataclasses import replace, FrozenInstanceError
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from core import broker_resource as resource
from core.file_read_schema import make_file_read_proposal
from core.structured_proposal import StructuredActionProposal


class BrokerResourceTests(unittest.TestCase):
    def setUp(self):
        self.owner = resource.BrokerFixtureOwner()
        self.addCleanup(self.owner.close)
        self.proposal = make_file_read_proposal('unverified requester description', max_bytes=128)
        self.decision = 'd'*64

    def bind(self):
        return self.owner.bind('app', self.proposal, self.decision)

    def verify(self, binding):
        return self.owner.verify_once(binding, 'app', self.proposal, self.decision)

    def test_created_handle_identity_and_no_content_read(self):
        description = self.owner.describe()
        self.assertEqual(description.size_bytes, 37)
        self.assertEqual(len(description.file_id), 16)
        self.assertFalse(os.get_inheritable(self.owner._fd))
        self.assertNotEqual(description.resource_token, description.session)
        with patch.object(resource.os, 'read', side_effect=AssertionError('no content read')):
            result = self.verify(self.bind())
        self.assertEqual(result.meaning, 'metadata matched; no read or permission')
        self.assertFalse(hasattr(result, 'data'))
        self.assertIsNone(self.owner._fd)
        self.assertFalse(Path(self.owner._path).exists())
        for item in (description, result):
            with self.assertRaises(TypeError): bool(item)

    def test_binding_is_exact_and_not_permission(self):
        binding = self.bind()
        self.assertIn(self.owner.describe().resource_token.encode(), binding.canonical_binding)
        with self.assertRaises(TypeError): bool(binding)
        with self.assertRaises(FrozenInstanceError): binding.session = 'x'
        self.verify(binding)
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_copied_binding_fails_and_burns_original(self):
        binding = self.bind()
        with self.assertRaises(resource.BrokerResourceError): self.verify(replace(binding))
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_foreign_owner_cannot_reuse_binding(self):
        binding = self.bind()
        with resource.BrokerFixtureOwner() as other:
            other.bind('app', self.proposal, self.decision)
            with self.assertRaises(resource.BrokerResourceError):
                other.verify_once(binding, 'app', self.proposal, self.decision)
        self.verify(binding)

    def test_all_request_substitutions_fail(self):
        cases = [('other', self.proposal, self.decision),
                 ('app', self.proposal, 'e'*64),
                 ('app', make_file_read_proposal('changed', max_bytes=128), self.decision),
                 ('app', make_file_read_proposal('unverified requester description', max_bytes=129), self.decision),
                 ('app', make_file_read_proposal('unverified requester description', max_bytes=128,
                                             requester_context={'note': 'changed'}), self.decision)]
        for app, proposal, decision in cases:
            with resource.BrokerFixtureOwner() as owner:
                binding = owner.bind('app', self.proposal, self.decision)
                with self.assertRaises(resource.BrokerResourceError):
                    owner.verify_once(binding, app, proposal, decision)
                with self.assertRaises(resource.BrokerResourceError): owner.describe()

    def test_mutated_binding_retired(self):
        binding = self.bind()
        object.__setattr__(binding, 'session', '0'*64)
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_mutated_observation_retired(self):
        description = self.owner.describe()
        object.__setattr__(description, 'file_id', b'x'*16)
        with self.assertRaises(resource.BrokerResourceError): self.bind()
        self.assertIsNone(self.owner._fd)

    def test_duplicate_binding_closes_owner(self):
        binding = self.bind()
        with self.assertRaises(resource.BrokerResourceError): self.bind()
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_invalid_attempt_closes_owner(self):
        with self.assertRaises(resource.BrokerResourceError): self.verify({})
        with self.assertRaises(resource.BrokerResourceError): self.bind()

    def test_bounds_and_types_fail_closed(self):
        for limit in (1, 36, 4097):
            with resource.BrokerFixtureOwner() as owner:
                with self.assertRaises(resource.BrokerResourceError):
                    owner.bind('app', make_file_read_proposal('label', max_bytes=limit), self.decision)
        for app, decision in [(True, self.decision), ('a'*257, self.decision), ('app', 'not-an-id'), ('app', {})]:
            with resource.BrokerFixtureOwner() as owner:
                with self.assertRaises(resource.BrokerResourceError): owner.bind(app, self.proposal, decision)

    def test_whole_file_boundary_and_maximum(self):
        for limit in (37, 4096):
            with resource.BrokerFixtureOwner() as owner:
                proposal = make_file_read_proposal('label', max_bytes=limit)
                binding = owner.bind('app', proposal, self.decision)
                owner.verify_once(binding, 'app', proposal, self.decision)

    def test_unsupported_effect_operation_and_attributes(self):
        invalid = [None, {}, StructuredActionProposal('files.delete', [{'type':'file','reference':'label'}]),
                   StructuredActionProposal('files.read', [{'type':'file','reference':'label','attributes':{'label':'changed'}}])]
        for proposal in invalid:
            with resource.BrokerFixtureOwner() as owner:
                with self.assertRaises(resource.BrokerResourceError): owner.bind('app', proposal, self.decision)

    def test_expired_before_bind_or_consume(self):
        binding = self.bind()
        with patch.object(resource, 'monotonic', return_value=self.owner._deadline):
            with self.assertRaises(resource.BrokerResourceError): self.verify(binding)
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_expiry_during_native_validation(self):
        binding = self.bind()
        original = self.owner._native.metadata
        clock = [self.owner._deadline-1]
        def metadata(*args):
            value = original(*args)
            clock[0] = self.owner._deadline
            return value
        with patch.object(resource, 'monotonic', side_effect=lambda: clock[0]), patch.object(self.owner._native, 'metadata', side_effect=metadata):
            with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_expiry_during_cleanup(self):
        binding = self.bind()
        original = self.owner.close
        clock = [self.owner._deadline-1]
        def close():
            original()
            clock[0] = self.owner._deadline
        with patch.object(resource, 'monotonic', side_effect=lambda: clock[0]), patch.object(self.owner, 'close', side_effect=close):
            with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_native_metadata_failure_retires(self):
        binding = self.bind()
        with patch.object(self.owner._native, 'metadata', side_effect=OSError('failure')):
            with self.assertRaises(resource.BrokerResourceError): self.verify(binding)
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_each_metadata_change_retires(self):
        for index in range(8):
            with resource.BrokerFixtureOwner() as owner:
                binding = owner.bind('app', self.proposal, self.decision)
                values = list(owner._metadata)
                values[index] = b'x'*16 if index == 1 else values[index]+1
                with patch.object(owner._native, 'metadata', return_value=tuple(values)):
                    with self.assertRaises(resource.BrokerResourceError):
                        owner.verify_once(binding, 'app', self.proposal, self.decision)

    def test_content_write_invalidates_metadata(self):
        binding = self.bind()
        os.write(self.owner._fd, b'changed')
        os.fsync(self.owner._fd)
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_replacement_cannot_retarget_retained_object(self):
        binding = self.bind()
        try:
            os.unlink(self.owner._path)
        except PermissionError:
            self.verify(binding)  # Windows refuses deletion of the held creator handle.
        else:
            self.fail('unexpected deletion of retained Windows fixture')

    def test_concurrent_consumption_exactly_once(self):
        binding = self.bind()
        barrier = threading.Barrier(3)
        results = []
        def worker():
            barrier.wait()
            try: results.append(self.verify(binding))
            except resource.BrokerResourceError: results.append(None)
        workers = [threading.Thread(target=worker) for _ in range(2)]
        for worker in workers: worker.start()
        barrier.wait()
        for worker in workers: worker.join(3); self.assertFalse(worker.is_alive())
        self.assertEqual(sum(value is not None for value in results), 1)

    def test_cleanup_failure_never_returns_match(self):
        binding = self.bind()
        original = resource.os.close
        def close(fd):
            original(fd)
            raise OSError('injected cleanup failure')
        with patch.object(resource.os, 'close', side_effect=close):
            with self.assertRaises(resource.BrokerResourceError): self.verify(binding)
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_context_cleanup_and_close_are_terminal(self):
        self.owner.close(); self.owner.close()
        self.assertFalse(Path(self.owner._path).exists())
        with self.assertRaises(resource.BrokerResourceError): self.owner.describe()

    def test_no_caller_resource_or_bootstrap_parameters(self):
        for kwargs in ({'path':'personal.txt'}, {'handle':1}, {'token':'x'}, {'contents':b'x'}, {'lifetime':9999}):
            with self.assertRaises(TypeError): resource.BrokerFixtureOwner(**kwargs)

    def test_hard_link_change_is_rejected(self):
        binding = self.bind()
        other = Path(self.owner._path + '.link')
        self.addCleanup(lambda: other.unlink(missing_ok=True))
        os.link(self.owner._path, other)
        with self.assertRaises(resource.BrokerResourceError): self.verify(binding)

    def test_invalid_randomness_fails_before_creation(self):
        with patch.object(resource.secrets, 'token_hex', return_value='a'*64), patch.object(resource.tempfile, 'mkstemp') as create:
            with self.assertRaises(resource.BrokerResourceError): resource.BrokerFixtureOwner()
            create.assert_not_called()

    def test_duplicate_ids_cannot_reopen_or_replace_fixture(self):
        with patch.object(resource.secrets, 'token_hex', side_effect=['a'*64,'b'*64,'a'*64,'b'*64]):
            with resource.BrokerFixtureOwner() as first:
                binding = first.bind('app', self.proposal, self.decision)
                with self.assertRaises(resource.BrokerResourceError): resource.BrokerFixtureOwner()
                first.verify_once(binding, 'app', self.proposal, self.decision)
