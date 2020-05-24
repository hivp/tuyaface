import json
import logging
import queue
import select
import socket
import threading
import time

from . import (_connect, _process_raw_reply, _select_command_reply, _send_request, _set_properties, _set_status, _status, tf)

logger = logging.getLogger(__name__)


HEART_BEAT_PING_TIME = 5
HEART_BEAT_PONG_TIME = 5

class TuyaClient(threading.Thread):

    """ Helper class to maintain a connection to and serialize access to a Tuya device. """
    def __init__(self, device: dict, on_status: callable=None, on_connection: callable=None):

        super().__init__()
        _set_properties(device)        
        self.device = device
        self.force_reconnect = False
        self.last_ping = 0
        self.last_pong = time.time()
        self.on_connection = on_connection
        self.on_status = on_status
        self.command_queue = queue.Queue()
        # socketpair used to interrupt the worker thread
        self.socketpair = socket.socketpair()
        self.stop = threading.Event()


    def _ping(self):
        """ Send a ping message. """

        self.last_ping = time.time()
        try:
            logger.debug("(%s) PING", self.device["ip"])
            _send_request(self.device, tf.HEART_BEAT)
        except socket.error:
            self.force_reconnect = True


    def _pong(self):
        """ Reset expired counter. """

        logger.debug("(%s) PONG", self.device["ip"])
        self.last_pong = time.time()


    def _is_connection_stale(self):
        """ Indicates if connection has expired. """

        if time.time() - self.last_ping > HEART_BEAT_PING_TIME:
            self._ping()

        return (time.time() - self.last_pong) > HEART_BEAT_PING_TIME + HEART_BEAT_PONG_TIME


    def _connect(self):

        if not self.device['tuyaface']['connection']:
            _connect(self.device)

        if self.on_connection:
            self.on_connection(True)
        self.last_pong = time.time()

    def _interrupt(self):

        try:
            # Write to the socket to interrupt the worker thread
            self.socketpair[1].send(b"x")
        except socket.error:
            # The socketpair may already be closed during shutdown, ignore it
            pass


    #TODO: nested too deep, split up in functions
    def run(self):

        while not self.stop.is_set():
            try:
                force_sleep = False
                if self.force_reconnect:
                    self.force_reconnect = False
                    logger.warning("(%s) reconnecting", self.device["ip"])
                    if self.device['tuyaface']['connection']:
                        try:
                            self.device['tuyaface']['connection'].close()
                        except Exception:
                            logger.exception("(%s) exception when closing socket", self.device["ip"], exc_info=False)
                        if self.on_connection:
                            self.on_connection(False)
                        self.device['tuyaface']['connection'] = None
                        continue

                if self.device['tuyaface']['connection'] == None:
                    try:
                        logger.debug("(%s) connecting", self.device["ip"])
                        self._connect()
                        logger.info("(%s) connected", self.device["ip"])
                        continue
                    except Exception:
                        logger.exception("(%s) exception when opening socket", self.device["ip"], exc_info=False)

                if self.device['tuyaface']['connection']:
                    # poll the socket, as well as the socketpair to allow us to be interrupted
                    rlist = [self.device['tuyaface']['connection'], self.socketpair[0]]
                    can_read = []
                    try:
                        can_read, _, _ = select.select(rlist, [], [], HEART_BEAT_PING_TIME/2)
                    except ValueError:
                        logger.exception("(%s) exception when waiting for socket", self.device["ip"], exc_info=False)
                        self.force_reconnect = True
                    if self.device['tuyaface']['connection'] in can_read:
                        try:
                            data = self.device['tuyaface']['connection'].recv(4096)
                            #logger.debug("(%s) read from socket '%s' (%s)", self.device["ip"], ''.join(format(x, '02x') for x in data), len(data))
                            if data:
                                for reply in _process_raw_reply(self.device, data):
                                    if reply["cmd"] == tf.HEART_BEAT:
                                        self._pong()
                                    if self.on_status and reply["cmd"] == tf.STATUS and reply["data"]:
                                        json_reply = json.loads(reply["data"])
                                        self.on_status(json_reply)
                            else:
                                # This may happen if the Tuya device has reached its maximum number of clients,
                                # sleep to prevent a cycle of repeatedly reconnecting
                                force_sleep = True
                        except socket.error:
                            logger.exception("(%s) exception when reading from socket", self.device["ip"], exc_info=False)
                            self.force_reconnect = True
                            # This may happen if the Tuya device has reached its maximum number of clients,
                            # sleep to prevent a cycle of repeatedly reconnecting
                            force_sleep = True

                    if self.socketpair[0] in can_read:
                        # Clear the socket's buffer
                        logger.debug("(%s) Interrupted", self.device["ip"])
                        self.socketpair[0].recv(128)

                    if self._is_connection_stale():
                        self.force_reconnect = True

                while not self.command_queue.empty():
                    command, args, reply_queue = self.command_queue.get()
                    result = command(*args)
                    reply_queue.put(result)

                if not self.device['tuyaface']['connection'] or force_sleep:
                    time.sleep(HEART_BEAT_PING_TIME/2)
            except Exception:
                logger.exception("(%s) Unexpected exception", self.device["ip"])


    def stop_client(self):
        """Close the connection and stop the worker thread"""

        self.stop.set()
        self._interrupt()
        self.join()


    def _status(self, _):

        if self.device['tuyaface']['connection'] == None:
            self._connect()
        try:
            status_reply, all_replies = _status(self.device)
            heartbeat = _select_command_reply(all_replies, tf.HEART_BEAT)
            if heartbeat:
                self._pong()
            if not status_reply:
                status_reply = {"data":"{}"}
            data = json.loads(status_reply["data"])
            return data
        except socket.error:
            self.force_reconnect = True


    def status(self):

        reply_queue = queue.Queue(1)
        self.command_queue.put((self._status, (None,), reply_queue))
        self._interrupt()
        reply = None
        try:
            reply = reply_queue.get(timeout=2)
            return reply
        except queue.Empty:
            logger.warning("(%s) No reply to status", self.device["ip"])


    def _set_state(self, value: bool, idx: int = 1):

        if self.device['tuyaface']['connection'] == None:
            self._connect()
        try:
            reply, all_replies = _set_status(self.device, {idx: value})
            for reply in all_replies:
                if reply["cmd"] == tf.HEART_BEAT:
                    self._pong()
                if self.on_status and reply["cmd"] == tf.STATUS and reply["data"]:
                    json_reply = json.loads(reply["data"])
                    self.on_status(json_reply)
            if not reply or ("rc" in reply and reply["rc"] != 0):
                return False
            return True
        except socket.error:
            self.force_reconnect = True


    def set_state(self, value: bool, idx: int = 1):

        reply_queue = queue.Queue(1)
        self.command_queue.put((self._set_state, (value, idx), reply_queue))
        self._interrupt()
        reply = None
        try:
            reply = reply_queue.get(timeout=2)
            return reply
        except queue.Empty:
            logger.warning("(%s) No reply to set_state", self.device["ip"])
