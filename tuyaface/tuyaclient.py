import json
import logging
import select
import socket
import threading
import time

from . import (_connect, _process_raw_reply, send_request, set_state, status, tf)

logger = logging.getLogger(__name__)


HEART_BEAT_PING_TIME = 5
HEART_BEAT_PONG_TIME = 5

class TuyaClient(threading.Thread):

    """ Helper class to maintain a connection to and serialize access to a Tuya device. """
    def __init__(self, device: dict, on_status: callable):

        super().__init__()
        self.connection = None
        self.device = device
        self.force_reconnect = False
        self.last_ping = 0
        self.last_pong = time.time()
        self.on_status = on_status
        self.seq=0
        # socketpair used to interrupt the worker thread
        self.socketpair = socket.socketpair()
        self.socket_lock = threading.Lock()
        self.stop = threading.Event()


    def _ping(self):
        """ Send a ping message. """

        self.last_ping = time.time()
        try:
            logger.debug("TuyaClient: PING")
            replies = list(reply for reply in send_request(self.device, tf.HEART_BEAT, connection=self.connection, seq=self.seq))
            self.seq += 1
            if replies:
                logger.debug("TuyaClient: PONG %s", replies)
                self._reset_pong()
        except socket.error:
            self.force_reconnect = True
            pass


    def _reset_pong(self):
        """ Reset expired counter. """

        self.last_pong = time.time()


    def _is_connection_stale(self):
        """ Indicates if connection has expired. """

        if time.time() - self.last_ping > HEART_BEAT_PING_TIME:
            self._ping()

        return (time.time() - self.last_pong) > HEART_BEAT_PING_TIME + HEART_BEAT_PONG_TIME


    def _connect(self):

        self.connection = _connect(self.device)
        self._reset_pong()

    def _interrupt(self):

        try:
            # Write to the socket to interrupt the worker thread
            self.socketpair[1].send(b"x")
        except socket.error:
            # The socketpair may already be closed during shutdown, ignore it
            pass


    def run(self):

        #self.connection = _connect(self.device)

        while not self.stop.is_set():
            try:
                data = None
                with self.socket_lock:
                    if self.force_reconnect:
                        self.force_reconnect = False
                        logger.warning("TuyaClient: reconnecting")
                        if self.connection:
                            try:
                                self.connection.close()
                            except Exception:
                                logger.exception("TuyaClient: exception when closing socket")
                                pass
                            self.connection = None

                    if self.connection == None:
                        try:
                            logger.debug("TuyaClient: connecting")
                            self._connect()
                            logger.info("TuyaClient: connected")
                        except Exception:
                            logger.exception("TuyaClient: exception when opening socket")
                            pass

                    if self.connection:
                        # poll the socket, as well as the socketpair to allow us to be interrupted
                        rlist = [self.connection, self.socketpair[0]]
                        can_read, a, b = select.select(rlist, [], [], HEART_BEAT_PING_TIME/2)
                        if self.connection in can_read:
                            try:
                                data = self.connection.recv(4096)
                                logger.debug("TuyaClient: read from socket '%s' (%s), %s, %s", data, len(data), a, b)
                                if data:
                                    for reply in _process_raw_reply(self.device, data):
                                        logger.debug("TuyaClient: Got msg %s", reply)
                                        if self.on_status:
                                            reply = json.loads(reply["data"])
                                            self.on_status(reply)
                            except socket.error:
                                logger.exception("TuyaClient: exception when reading from socket")
                                self.force_reconnect = True
                                pass

                        if self.socketpair[0] in can_read:
                            # Clear the socket's buffer
                            logger.debug("TuyaClient: Interrupted")
                            self.socketpair[0].recv(128)

                        if self._is_connection_stale():
                             self.force_reconnect = True

                if not self.connection or not data:
                #if not self.connection:
                    time.sleep(HEART_BEAT_PING_TIME/2)
            except Exception:
                logger.exception("TuyaClient: Unexpected exception")


    #TODO: code is hidden by line 30
    def stop(self):

        self.stop.set()
        self._interrupt()
        self.join()


    def status(self):

        with self.socket_lock:
            if self.connection == None:
                self._connect()
            try:
                data = status(self.device, connection=self.connection, seq=self.seq)
                self.seq += 1
                return data
            except socket.error:
                self.force_reconnect = True


    def set_state(self, value: bool, idx: int = 1):

        with self.socket_lock:
            if self.connection == None:
                self._connect()
            try:
                data = set_state(self.device, value, idx, connection=self.connection, seq=self.seq)
                self.seq += 1
                return data
            except socket.error:
                self.force_reconnect = True
