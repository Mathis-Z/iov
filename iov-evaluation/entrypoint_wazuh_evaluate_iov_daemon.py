"""PyInstaller entrypoint for the `wazuh-evaluate-iov-daemon` binary."""

from evaluate_iov.daemon import run_entrypoint

if __name__ == "__main__":
    run_entrypoint()
