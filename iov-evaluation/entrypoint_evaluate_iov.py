"""PyInstaller entrypoint for the standalone `evaluate-iov` binary."""

from evaluate_iov.cli import run

if __name__ == "__main__":
    run()
