"""Human-operated walkthrough using only bootstrap-generated synthetic fixtures.

Run: python -m core.controlled_read_demo
No paths, approval flags, fake clock or unattended input are accepted.
"""
from dataclasses import asdict
import json
import os
import sys
from time import sleep
from pathlib import Path

from .file_read_schema import make_file_read_proposal
from .fixture_read_experiment import (FixtureReadExperiment, FIXTURE_REFERENCE,
                                      ProtectedReadResult, MAX_FIXTURE_BYTES)
from .registry import ApplicationRegistry


class _Stopped(Exception):
    pass


class _ApprovalUnavailable(Exception):
    pass


def _choose(experiment, request, label, *, allow):
    print('\n' + label)
    display = experiment.operator_port.review(request)
    print('Application:', display.application_id, '| Action: files.read | Maximum bytes:', display.max_bytes)
    print('Observed resource and exact request (paths are display labels, not identity):')
    print(json.dumps(asdict(display), ensure_ascii=True, indent=2))
    phrase = 'ALLOW ONCE' if allow else 'DENY'
    print('This review expires 60 seconds after the request; answer promptly. Expiry never extends automatically.')
    answer = input('For this stage type ' + phrase + ' (anything else stops safely): ')
    if answer != phrase:
        experiment.operator_port.deny(request)
        raise _Stopped()
    if allow:
        if not experiment.operator_port.approve(display):
            raise _ApprovalUnavailable()
    elif not experiment.operator_port.deny(request):
        raise RuntimeError('request no longer available')


def _report(label, result, *, allowed):
    expected_reason = 'controlled_read_released' if allowed else 'controlled_read_denied'
    if (type(result) is not ProtectedReadResult or type(result.data) is not bytes
            or result.released is not allowed or result.reason != expected_reason
            or len(result.data) > MAX_FIXTURE_BYTES or (not allowed and result.data)):
        raise RuntimeError('unexpected protected read result')
    print(label + ' — PASS — ' + ('ALLOW' if result.released else 'DENY') + ': ' + str(len(result.data)) + ' protected bytes released.')
    if result.released:
        print('Application received synthetic data:', repr(result.data))


def _revoked_case(experiment, request, credential, proposal):
    if experiment.operator_port.revoke_review(request) is not True:
        raise RuntimeError('revocation was not confirmed')
    print('Revocation confirmed. Submitting the old request to verify rejection; this is not a native file read.')
    result = experiment.application_port.read_once(request, 'controlled-demo-app', credential, proposal)
    _report('Revoked approval', result, allowed=False)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv or os.name != 'nt' or not sys.stdin.isatty():
        print('Requires Windows and an interactive operator terminal; no arguments are accepted.')
        return 2
    stage = 'fixture setup'
    registry = ApplicationRegistry()
    try:
        credential = registry.register('controlled-demo-app', ['files.read'])
        with FixtureReadExperiment(registry) as experiment:
            app = experiment.application_port
            proposal = make_file_read_proposal(FIXTURE_REFERENCE, max_bytes=128)
            def propose(value=proposal):
                return app.propose('controlled-demo-app', credential, value)
            def read(request, value=proposal):
                return app.read_once(request, 'controlled-demo-app', credential, value)
            print('Walkthrough build: revocation-reporting.v2')
            print('Demo module:', str(Path(__file__).resolve()))
            print('OWNER DEMONSTRATION — generated fixtures only; no personal files.')
            print('Nine decisions; approximately 2–4 minutes, including a real 65-second expiry wait.')
            print('This controls this integration path, not direct Windows access or immutable bytes.')
            stage = '1. explicit denial'
            request = propose()
            _choose(experiment, request, '1. Explicit DENY', allow=False)
            _report('Owner denial', read(request), allowed=False)

            stage = '2. one-use approval'
            request = propose()
            _choose(experiment, request, '2. ALLOW ONCE', allow=True)
            _report('First bounded read', read(request), allowed=True)
            stage = '3. consumed-approval replay'
            _report('3. Replay of consumed approval', read(request), allowed=False)

            stage = '4a. operator approval before revocation'
            request = propose()
            _choose(experiment, request, '4a. Approve, then revoke before use', allow=True)
            stage = '4a. revoke and verify denial'
            _revoked_case(experiment, request, credential, proposal)

            stage = '4b. stale-grant case'
            request = propose()
            _choose(experiment, request, '4b. Approve, then change the registry grant version', allow=True)
            registry.set_scopes('controlled-demo-app', ['files.read'])
            print('Grant version changed without broadening its scopes; previous evidence is stale.')
            _report('Stale grant approval', read(request), allowed=False)

            stage = '4c. real expiry case'
            request = propose()
            _choose(experiment, request, '4c. Approve, then let its real deadline expire', allow=True)
            print('Waiting 65 real seconds. No clock or deadline is modified.')
            for remaining in range(65, 0, -1):
                if remaining in (65, 45, 30, 15, 5):
                    print(str(remaining) + ' seconds remaining...', flush=True)
                sleep(1)
            _report('Expired approval', read(request), allowed=False)

            stage = '5a. changed request'
            request = propose()
            _choose(experiment, request, '5a. Approve this request, then substitute a changed byte effect', allow=True)
            changed = make_file_read_proposal(FIXTURE_REFERENCE, max_bytes=127)
            _report('Changed request cannot inherit approval', read(request, changed), allowed=False)
            stage = '5b. fresh approval for changed request'
            request = propose(changed)
            _choose(experiment, request, '5b. Fresh approval is required for the changed request', allow=True)
            _report('Newly approved changed request', read(request, changed), allowed=True)

            stage = '6a. changed resource'
            request = propose()
            _choose(experiment, request, '6a. Approve the original resource before substitution', allow=True)
            with FixtureReadExperiment(registry, fixture_data=b'Second harmless generated fixture\n') as other:
                other_app = other.application_port
                result = other_app.read_once(request, 'controlled-demo-app', credential, proposal)
                _report('Different resource/session cannot inherit approval', result, allowed=False)
                stage = '6b. fresh approval for new resource'
                fresh = other_app.propose('controlled-demo-app', credential, proposal)
                _choose(other, fresh, '6b. Inspect the new resource identity and approve it separately', allow=True)
                result = other_app.read_once(fresh, 'controlled-demo-app', credential, proposal)
                _report('Newly approved resource', result, allowed=True)
            print('\nAll owner demonstration stages completed. No broader protection is claimed.')
            return 0
    except _Stopped:
        print('Owner stopped the demonstration; the pending request was denied.')
        return 0
    except _ApprovalUnavailable:
        print('FAIL — stage ' + stage + ': operator approval was not accepted; the review expired, changed or became unavailable.')
        print('This stage stopped before its read/revocation test. No PASS is claimed. Rerun for a fresh review.')
        return 1
    except (Exception, KeyboardInterrupt):
        print('FAIL — stage ' + stage + ' did not complete verification; it is not a PASS.')
        print('No fallback or retry was attempted. A review can expire while awaiting input; rerun for fresh requests.')
        return 1
    finally:
        registry.close()


if __name__ == '__main__':
    raise SystemExit(main())
