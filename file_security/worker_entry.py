"""Private fixed worker entry point. Input is bytes on stdin, never code/paths."""

import json
from pathlib import Path
import sys

# The launcher uses isolated Python (-I -S). Only this installed project root
# is explicitly added; caller cwd and PYTHONPATH are not import locations.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from file_security.text_analysis import MAX_BYTES, analyze_bytes


def main():
    content = sys.stdin.buffer.read(MAX_BYTES + 1)
    result = analyze_bytes(content)
    sys.stdout.buffer.write(json.dumps(result.to_dict(), ensure_ascii=True, allow_nan=False).encode('ascii'))
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
