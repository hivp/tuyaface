"""Helper to maintain a connection to and serialize access to a Tuya device."""
import json
import logging
import queue
import select
import socket
import threading
import time

from . import (
    _connect,
    _process_raw_reply,
    _select_command_reply,
    _send_request,
    _set_properties,
    _set_status,
    _status,
)
from .const import CMD_TYPE

logger = logging.getLogger(__name__)


HEART_BEAT_TIME = 7
CONNECTION_STALE_TIME = 7
RECONNECT_COOL_DOWN_TIME = 5


class TuyaClient(threading.Thread):
    """Helper class to maintain a connection to and serialize access to a Tuya device."""

    def __init__(
        self, device: dict, on_status: callable = None, on_connection: callable = None
    ):
        """Initialize the Tuya client."""

        super().__init__()
        _set_properties(device)
        self.device = device
        self.force_reconnect = False
        self.last_msg_rcv = time.time()
        self.last_reconnect = 0
        self.on_connection = on_connection
        self.on_status = on_status
        self.command_queue = queue.Queue()
        # socketpair used to interrupt the worker thread
        self.socketpair = socket.socketpair()
        self.stop = threading.Event()

    def _ping(self):
        """Send a ping message."""

        try:
            logger.debug("(%s) PING", self.device["ip"])
            _send_request(self.device, CMD_TYPE.HEART_BEAT)
        except socket.error:
            logger.debug(
                "(%s) exception when sending heartbeat", self.device["ip"],
            )
            self.force_reconnect = True

    def _pong(self):
        """Reset expired counter."""

        logger.debug("(%s) PONG", self.device["ip"])

    def _is_connection_stale(self):
        """Indicate if connection has expired."""

        if time.time() - self.last_msg_rcv > HEART_BEAT_TIME:
            self._ping()

        return (
            time.time() - self.last_msg_rcv
        ) > HEART_BEAT_TIME + CONNECTION_STALE_TIME

    def _connect(self):

        if not self.device["tuyaface"]["connection"]:
            _connect(self.device)

        if self.on_connection:
            self.on_connection(True)
        self.last_msg_rcv = time.time()

    def _interrupt(self):

        try:
            # Write to the socket to interrupt the worker thread
            self.socketpair[1].send(b"x")
        except socket.error:
            # The socketpair may already be closed during shutdown, ignore it
            pass

    def run(self):
        """Tuya client main loop."""
        # TODO: nested too deep, split up in functions
        while not self.stop.is_set():  # pylint: disable=too-many-nested-blocks
            try:
                if self.force_reconnect:
                    self.force_reconnect = False
                    logger.warning("(%s) reconnecting", self.device["ip"])
                    now = time.time()
                    if now - self.last_reconnect < RECONNECT_COOL_DOWN_TIME:
                        logger.debug(
                            "(%s) waiting before reconnecting", self.device["ip"]
                        )
                        # Sleep to prevent a cycle of repeatedly reconnecting
                        time.sleep(
                            RECONNECT_COOL_DOWN_TIME - (now - self.last_reconnect)
                        )
                    self.last_reconnect = time.time()
                    if self.device["tuyaface"]["connection"]:
                        try:
                            self.device["tuyaface"]["connection"].close()
                        except socket.error:
                            logger.exception(
                                "(%s) exception when closing socket",
                                self.device["ip"],
                                exc_info=False,
                            )
                        if self.on_connection:
                            self.on_connection(False)
                        self.device["tuyaface"]["connection"] = None
                        continue

                if self.device["tuyaface"]["connection"] is None:
                    try:
                        logger.debug("(%s) connecting", self.device["ip"])
                        self._connect()
                        logger.info("(%s) connected", self.device["ip"])
                        continue
                    except socket.error:
                        logger.exception(
                            "(%s) exception when opening socket",
                            self.device["ip"],
                            exc_info=False,
                        )

                if self.device["tuyaface"]["connection"]:
                    # poll the socket, as well as the socketpair to allow us to be interrupted.
                    rlist = [self.device["tuyaface"]["connection"], self.socketpair[0]]
                    can_read = []
                    try:
                        can_read, _, _ = select.select(
                            rlist, [], [], CONNECTION_STALE_TIME / 2
                        )
                    except ValueError:
                        logger.exception(
                            "(%s) exception when waiting for socket",
                            self.device["ip"],
                            exc_info=False,
                        )
                        self.force_reconnect = True
                    if self.device["tuyaface"]["connection"] in can_read:
                        try:
                            data = self.device["tuyaface"]["connection"].recv(4096)
                            # logger.debug("(%s) read from socket '%s' (%s)", self.device["ip"], ''.join(format(x, '02x') for x in data), len(data))
                            if data:
                                for reply in _process_raw_reply(self.device, data):
                                    self.last_msg_rcv = time.time()
                                    if reply["cmd"] == CMD_TYPE.HEART_BEAT:
                                        self._pong()
                                    if (
                                        self.on_status
                                        and reply["cmd"] == CMD_TYPE.STATUS
                                        and reply["data"]
                                    ):
                                        json_reply = json.loads(reply["data"])
                                        self.on_status(json_reply, "status")
                            else:
                                self.force_reconnect = True
                        except socket.error:
                            logger.exception(
                                "(%s) exception when reading from socket",
                                self.device["ip"],
                                exc_info=False,
                            )
                            self.force_reconnect = True

                    if self.socketpair[0] in can_read:
                        # Clear the socket's buffer
                        logger.debug("(%s) Interrupted", self.device["ip"])
                        self.socketpair[0].recv(128)

                    if self._is_connection_stale():
                        logger.debug(
                            "(%s) connection stale", self.device["ip"],
                        )
                        self.force_reconnect = True

                while not self.command_queue.empty():
                    command, args, reply_queue = self.command_queue.get()
                    result = command(*args)
                    reply_queue.put(result)

                if not self.device["tuyaface"]["connection"]:
                    time.sleep(RECONNECT_COOL_DOWN_TIME / 2)
            except Exception:  # pylint: disable=broad-except
                logger.exception("(%s) Unexpected exception", self.device["ip"])

    def stop_client(self):
        """Close the connection and stop the worker thread."""

        self.stop.set()
        self._interrupt()
        self.join()

    def _status(self, _):

        if self.device["tuyaface"]["connection"] is None:
            try:
                self._connect()
            except socket.error:
                return
        try:
            status_reply, all_replies = _status(self.device)
            if all_replies:
                self.last_msg_rcv = time.time()
            heartbeat = _select_command_reply(
                self.device, all_replies, CMD_TYPE.HEART_BEAT
            )
            if heartbeat:
                self._pong()
            if not status_reply:
                status_reply = {"data": "{}"}
            data = json.loads(status_reply["data"])
            self.device["tuyaface"]["status"] = data
            self.device["tuyaface"]["status_reply_on"] = "status"
            return data
        except socket.error:
            logger.debug(
                "(%s) exception when updating status", self.device["ip"],
            )
            self.force_reconnect = True

    def status(self) -> dict:
        """Request status."""
        reply_queue = queue.Queue(1)
        self.command_queue.put((self._status, (None,), reply_queue))
        self._interrupt()
        reply = None
        try:
            reply = reply_queue.get(timeout=2)
            return reply
        except queue.Empty:
            logger.warning("(%s) No reply to status", self.device["ip"])

    def _set_state(self, value: dict, idx: int = 1):

        if self.device["tuyaface"]["connection"] is None:
            try:
                self._connect()
            except socket.error:
                return
        try:
            state_reply, all_replies = _set_status(self.device, value)
            if all_replies:
                self.last_msg_rcv = time.time()
            for reply in all_replies:
                if reply["cmd"] == CMD_TYPE.HEART_BEAT:
                    self._pong()
                if self.on_status and reply["cmd"] == CMD_TYPE.STATUS and reply["data"]:
                    json_reply = json.loads(reply["data"])
                    self.on_status(json_reply, "command")
            if not state_reply or ("rc" in state_reply and state_reply["rc"] != 0):
                return False
            return True
        except socket.error:
            logger.debug(
                "(%s) exception when setting state", self.device["ip"],
            )
            self.force_reconnect = True

    def set_state(self, value, idx: int = 1) -> dict:
        """Set state."""
        if not isinstance(value, (bool, float, int, str)):
            raise ValueError(f"Type {type(value)} not acceptable")

        reply_queue = queue.Queue(1)
        self.command_queue.put((self._set_state, ({idx: value}, idx), reply_queue))
        self._interrupt()
        reply = None
        try:
            reply = reply_queue.get(timeout=2)
            return reply
        except queue.Empty:
            logger.warning("(%s) No reply to set_state", self.device["ip"])

    def set_status(self, value: dict) -> dict:
        """Set status."""
        if not isinstance(value, dict):
            raise ValueError(f"Type {type(value)} not acceptable")

        reply_queue = queue.Queue(1)
        self.command_queue.put((self._set_state, (value,), reply_queue))
        self._interrupt()
        reply = None
        try:
            reply = reply_queue.get(timeout=2)
            return reply
        except queue.Empty:
            logger.warning("(%s) No reply to set_status", self.device["ip"])
