"""Publishing events through the local Wazuh agent's queue socket.

The agent forwards whatever is written here to the manager, so the daemon needs
no credentials of its own: the manager decodes the event, matches a rule and
routes it to the index. Messages are framed as

    <queue_id>:<location>:<message>

which is the format Wazuh's own integration scripts use. The message is pure
JSON so analysisd's built-in JSON decoding picks the fields apart.
"""

import json
import logging
import socket
from pathlib import Path

from .logging_setup import LOGGER_NAME

log = logging.getLogger(LOGGER_NAME)

# Wazuh 4.x, with the pre-4.x location as a fallback.
SOCKET_PATHS = ("/var/ossec/queue/sockets/queue", "/var/ossec/queue/ossec/queue")

QUEUE_ID = "1"
DEFAULT_LOCATION = "evaluate-iov"

# analysisd drops oversized events, so stay well under the datagram limit.
MAX_EVENT_BYTES = 60 * 1024


class QueueError(Exception):
    """The event could not be handed to the agent."""


def default_socket_path() -> str:
    """The agent's queue socket, preferring the Wazuh 4.x location."""
    for path in SOCKET_PATHS:
        if Path(path).exists():
            return path
    return SOCKET_PATHS[0]


def frame(location: str, payload: dict) -> bytes:
    """Encode an event in the queue's wire format."""
    return f"{QUEUE_ID}:{location}:{json.dumps(payload)}".encode()


def send_event(socket_path: str, location: str, payload: dict) -> None:
    """Hand one event to the agent. Raises QueueError if it cannot be sent."""
    message = frame(location, payload)
    if len(message) > MAX_EVENT_BYTES:
        raise QueueError(f"event is {len(message)} bytes, over the {MAX_EVENT_BYTES} limit")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(socket_path)
            sock.send(message)
    except OSError as exc:
        raise QueueError(f"{socket_path}: {exc}") from exc

    log.debug("sent %d byte(s) to %s", len(message), socket_path)
