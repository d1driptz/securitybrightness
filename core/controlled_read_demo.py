"""Interactive, opt-in synthetic fixture demonstration; no arbitrary paths.

Run from the repository with: python -m core.controlled_read_demo
The local terminal is the trusted operator channel for this experiment only.
"""
from dataclasses import asdict
import json
import os
import sys

from .file_read_schema import make_file_read_proposal
from .fixture_read_experiment import FixtureReadExperiment, FIXTURE_REFERENCE
from .registry import ApplicationRegistry


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv or os.name != 'nt' or not sys.stdin.isatty():
        print('Requires Windows and an interactive operator terminal; no arguments are accepted.')
        return 2
    registry = ApplicationRegistry()
    try:
        credential = registry.register('controlled-demo-app', ['files.read'])
        with FixtureReadExperiment(registry) as experiment:
            app, operator = experiment.application_port, experiment.operator_port
            proposal = make_file_read_proposal(FIXTURE_REFERENCE, max_bytes=128)
            request = app.propose('controlled-demo-app', credential, proposal)
            denied = app.read_once(request, 'controlled-demo-app', credential, proposal)
            if denied.released or denied.data:
                raise RuntimeError('initial denial failed')
            print('Without operator approval: DENY, 0 protected bytes released.')
            request = app.propose('controlled-demo-app', credential, proposal)
            display = operator.review(request)
            print('Review the synthetic fixture only. This does not protect other Windows file access.')
            print(json.dumps(asdict(display), ensure_ascii=True, indent=2))
            answer = input('Type APPROVE FIXTURE ONCE to permit this read; anything else denies: ')
            if answer == 'APPROVE FIXTURE ONCE':
                if not operator.approve(display):
                    raise RuntimeError('review no longer current')
            else:
                operator.deny(request)
            result = app.read_once(request, 'controlled-demo-app', credential, proposal)
            print(('ALLOW' if result.released else 'DENY') + ': ' + str(len(result.data)) + ' protected bytes released.')
            if result.released:
                print('Application received:', repr(result.data))
            replay = app.read_once(request, 'controlled-demo-app', credential, proposal)
            if replay.released or replay.data:
                raise RuntimeError('replay denial failed')
            print('Replay: DENY, 0 protected bytes released.')
            return 0
    except (Exception, KeyboardInterrupt):
        print('Controlled experiment stopped or failed; no fallback operation was attempted.')
        return 1
    finally:
        registry.close()


if __name__ == '__main__':
    raise SystemExit(main())
