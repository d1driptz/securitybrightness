"""Fixed one-file read helper; path arrives through stdin, content through stdout."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from file_security.acquisition import ACQUISITION_FAILURES, MAX_PATH_MESSAGE, FileInputError, read_selected_file


def main():
    message = sys.stdin.buffer.read(MAX_PATH_MESSAGE + 1)
    if len(message) > MAX_PATH_MESSAGE:
        return 20
    try:
        path = json.loads(message.decode('utf-8'))
        content = read_selected_file(path)
    except FileInputError as error:
        return ACQUISITION_FAILURES.get(str(error), 25)
    except (ValueError, TypeError, RecursionError):
        return 20
    sys.stdout.buffer.write(content)
    sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    sys.exit(main())
