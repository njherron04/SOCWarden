# tail_log.py
import time
import argparse
from pathlib import Path

def tail_f(path: Path, sleep: float = 0.25):
    # open in read-only, seek to end
    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                print(line.rstrip("\n"))
            else:
                time.sleep(sleep)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Minimal tail -f")
    p.add_argument("file", type=Path, help="Path to log file")
    p.add_argument("--sleep", type=float, default=0.25, help="Polling interval seconds")
    args = p.parse_args()
    if not args.file.exists():
        print(f"File not found: {args.file}")
        raise SystemExit(1)
    tail_f(args.file, args.sleep)
