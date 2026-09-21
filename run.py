"""Start the PICO web console.

    python run.py                 http://127.0.0.1:8000
    python run.py --port 9000
"""

import argparse

from pico.cli import cmd_serve


def main() -> int:
    parser = argparse.ArgumentParser(description="Start the PICO web console.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true",
                        help="restart on source changes (development)")
    return cmd_serve(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
