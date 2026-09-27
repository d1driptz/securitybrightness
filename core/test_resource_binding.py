import unittest
from dataclasses import replace, FrozenInstanceError
from unittest.mock import patch

from core.file_read_schema import make_file_read_proposal
from core.resource_binding import AdapterObservationSession


class ResourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.session = AdapterObservationSession()
        self.report = dict(volume_serial=1, file_id=b"a" * 16, size_bytes=8, change_time=10,
                           display_path="C:/display/notes.txt", filesystem="local_ntfs",
                           file_kind="regular", reparse_status="excluded")
        self.observation = self.session.record_observation(**self.report)
        self.proposal = make_file_read_proposal("requester-label", max_bytes=16)
        self.binding = self.session.bind("app", self.proposal, self.observation)

    def matches(self, binding=None, observation=None, proposal=None, application_id="app"):
        return self.session.matches(self.binding if binding is None else binding, application_id,
                                    self.proposal if proposal is None else proposal,
                                    self.observation if observation is None else observation).matches

    def test_requester_and_display_strings_are_not_resource_identity(self):
        self.assertTrue(self.matches())
        self.assertNotEqual(self.proposal.to_payload()["resources"][0]["reference"],
                            self.observation.display_path)
        same_path_other_file = self.session.record_observation(**{**self.report, "file_id": b"b" * 16})
        self.assertFalse(self.matches(observation=same_path_other_file))
        alias = self.session.record_observation(**{**self.report, "display_path": "C:/alias.txt"})
        self.assertFalse(self.matches(observation=alias))

    def test_copied_requester_or_cross_session_observations_cannot_be_promoted(self):
        for observation in (dict(self.report), replace(self.observation)):
            with self.assertRaises(ValueError):
                self.session.bind("app", self.proposal, observation)
        other = AdapterObservationSession().record_observation(**self.report)
        with self.assertRaises(ValueError):
            self.session.bind("app", self.proposal, other)
        self.assertFalse(self.matches(binding=replace(self.binding)))

    def test_replacement_same_metadata_or_different_identity_invalidates_old_binding(self):
        for changes in ({}, {"volume_serial": 2}, {"file_id": b"b" * 16},
                        {"size_bytes": 9}, {"change_time": 11}):
            session = AdapterObservationSession()
            old = session.record_observation(**self.report)
            binding = session.bind("app", self.proposal, old)
            new = session.replace_observation(old, **{**self.report, **changes})
            self.assertFalse(session.matches(binding, "app", self.proposal, old).matches)
            self.assertFalse(session.matches(binding, "app", self.proposal, new).matches)

    def test_release_and_failed_replacement_are_terminal_for_old_evidence(self):
        with self.assertRaises(ValueError):
            self.session.replace_observation(self.observation, **{**self.report, "reparse_status": "unknown"})
        self.assertFalse(self.matches())
        with self.assertRaises(ValueError):
            self.session.bind("app", self.proposal, self.observation)
        self.session.release(self.observation)
        self.assertFalse(self.matches())

    def test_proposal_owner_effect_and_context_changes_require_new_binding(self):
        self.assertFalse(self.matches(application_id="other"))
        for proposal in (make_file_read_proposal("requester-label", max_bytes=15),
                         make_file_read_proposal("changed-label", max_bytes=16),
                         make_file_read_proposal("requester-label", max_bytes=16,
                                                 requester_context={"purpose": "new"})):
            self.assertFalse(self.matches(proposal=proposal))
        self.assertTrue(self.matches())

    def test_oversized_observation_cannot_fit_and_invalid_attempt_does_not_supersede(self):
        for size in (0, 16):
            observation = self.session.record_observation(**{**self.report, "size_bytes": size})
            self.session.bind("app", self.proposal, observation)
        observation = self.session.record_observation(**{**self.report, "size_bytes": 17})
        with self.assertRaises(ValueError):
            self.session.bind("app", self.proposal, observation)
        with self.assertRaises(ValueError):
            self.session.bind("app", make_file_read_proposal("requester-label", max_bytes=7), self.observation)
        self.assertTrue(self.matches())

    def test_unknown_reparse_network_nonregular_and_incomplete_profiles_rejected(self):
        for key, value in (("filesystem", "smb"), ("filesystem", "unknown"),
                           ("file_kind", "directory"), ("file_kind", "device"),
                           ("reparse_status", "present"), ("reparse_status", "unknown"),
                           ("reparse_status", True)):
            with self.assertRaises(ValueError):
                self.session.record_observation(**{**self.report, key: value})
        for key in self.report:
            incomplete = dict(self.report)
            del incomplete[key]
            with self.assertRaises(TypeError):
                self.session.record_observation(**incomplete)

    def test_metadata_types_are_strict_and_display_path_is_not_normalized(self):
        for key in ("volume_serial", "size_bytes", "change_time"):
            for value in (True, -1, 2**64, 1.0, "1", None):
                with self.assertRaises(ValueError):
                    self.session.record_observation(**{**self.report, key: value})
        for value in (b"a" * 15, b"a" * 17, "a" * 16, bytearray(b"a" * 16)):
            with self.assertRaises(ValueError):
                self.session.record_observation(**{**self.report, "file_id": value})
        for value in ("", " ", "x\x00", "\ud800", "x" * 32768):
            with self.assertRaises(ValueError):
                self.session.record_observation(**{**self.report, "display_path": value})
        value = " C:/display/notes.txt "
        self.assertEqual(self.session.record_observation(**{**self.report, "display_path": value}).display_path, value)

    def test_immutability_and_boolean_guards_do_not_claim_permission(self):
        for value in (self.observation, self.binding,
                      self.session.matches(self.binding, "app", self.proposal, self.observation)):
            with self.assertRaises(TypeError):
                bool(value)
        with self.assertRaises(FrozenInstanceError):
            self.observation.size_bytes = 1
        self.assertNotIn(self.report["display_path"], repr(self.observation))
        new = self.session.bind("app", self.proposal, self.observation)
        self.assertFalse(self.matches())
        self.assertTrue(self.matches(binding=new))

    def test_capacity_and_identity_collision_cannot_restore_released_evidence(self):
        session = AdapterObservationSession(capacity=1)
        observation = session.record_observation(**self.report)
        session.release(observation)
        with self.assertRaises(ValueError):
            session.record_observation(**self.report)
        self.session.release(self.observation)
        with patch("core.resource_binding.uuid4", return_value=self.observation.observation_id):
            with self.assertRaises(RuntimeError):
                self.session.record_observation(**self.report)
        self.assertFalse(self.matches())

    def test_requester_context_does_not_supply_or_replace_adapter_observation(self):
        proposal = make_file_read_proposal("requester-label", max_bytes=16,
            requester_context={"observation_id": self.observation.observation_id,
                               "volume_serial": 1, "file_id": "a" * 32,
                               "reparse_status": "excluded", "verified": True})
        self.assertFalse(self.matches(proposal=proposal))
        with self.assertRaises(ValueError):
            self.session.bind("app", proposal, proposal.to_payload()["requester_context"])

    def test_model_never_opens_files_or_calls_path_resolution(self):
        with patch("builtins.open", side_effect=AssertionError("file opened")), \
             patch("os.open", side_effect=AssertionError("file opened")), \
             patch("pathlib.Path.resolve", side_effect=AssertionError("path resolved")), \
             patch("pathlib.Path.stat", side_effect=AssertionError("file inspected")):
            observation = self.session.record_observation(**self.report)
            binding = self.session.bind("app", self.proposal, observation)
            self.assertTrue(self.session.matches(binding, "app", self.proposal, observation).matches)
            self.session.release(observation)

    def test_closed_session_cannot_restore_or_issue_evidence(self):
        self.session.close()
        self.session.close()
        self.assertFalse(self.matches())
        with self.assertRaises(ValueError):
            self.session.bind("app", self.proposal, self.observation)
        with self.assertRaises(ValueError):
            self.session.record_observation(**self.report)

    def test_unhashable_fabricated_identity_and_utf16_oversize_fail_closed(self):
        forged = replace(self.observation, observation_id=[])
        self.assertFalse(self.matches(observation=forged))
        self.session.release(forged)
        self.assertTrue(self.matches())
        with self.assertRaises(ValueError):
            self.session.record_observation(**{**self.report, "display_path": "\U0001f600" * 16384})

    def test_unknown_fields_schema_versions_and_operations_cannot_bind(self):
        from core.structured_proposal import StructuredActionProposal
        with self.assertRaises(TypeError):
            self.session.record_observation(**{**self.report, "approved": True})
        payload = self.proposal.to_payload()
        for operation, effects in (("files.write", payload["effects"]),
                                   ("files.read", {**payload["effects"], "schema": "file_read.v2"}),
                                   ("files.read", {**payload["effects"], "recipient": "other"})):
            proposal = StructuredActionProposal(operation, payload["resources"], effects=effects)
            with self.assertRaises(ValueError):
                self.session.bind("app", proposal, self.observation)
        self.assertTrue(self.matches())

    def test_registry_revocation_does_not_turn_resource_match_into_permission(self):
        from core.registry import ApplicationRegistry
        registry = ApplicationRegistry()
        registry.register("app", ["files.read"])
        registry.revoke("app")
        # Resource matching is intentionally independent. Consumers MUST compose
        # it with live authority evidence; this is never an allow result.
        self.assertTrue(self.matches())
        registry.close()
