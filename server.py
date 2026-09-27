""" HONEYPOT WITH PARAMIKO AND SOCKET MODULE """
import socket
import os
import threading
import subprocess
import paramiko
from paramiko.ssh_exception import SSHException
from paramiko.common import (AUTH_FAILED,
                             AUTH_SUCCESSFUL,
                             OPEN_SUCCEEDED,
                             OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                             )
from logger import setup_logger
from dotenv import load_dotenv

load_dotenv()


class ServerParamiko(paramiko.ServerInterface):
    """ SERVER PARAMIKO """
    def __init__(self):
        self.allowed_method = 'password'
        self.channel = None
        self.success_message = AUTH_SUCCESSFUL
        self.failed_operation_message = AUTH_FAILED
        self.logger = setup_logger()

    def get_allowed_auths(self, username: str):
        return self.allowed_method

    def check_auth_password(self, username: str, password: str):
        """
        CHECK AND SET
        - username
        - password
        """
        # try:
        #     validator = ValidatePassword(password)
        #     validator.is_upper()
        #     validator.is_lower()
        #     validator.has_symbols()
        #     validator.has_digits()
        # except Exception as e:
        #     print(e)
        if username == os.getenv('username') and password == os.getenv('password'):
            return self.success_message
        return self.failed_operation_message

    def check_channel_request(self, kind, chanid) -> int:
        if kind == 'session':
            return OPEN_SUCCEEDED or 0
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_exec_request(self, channel, cmd):
        try:
            with open('log.txt', 'w', encoding='utf-8') as log:
                response = subprocess.run(cmd, shell=True,
                                          stdout=log
                                          )
                self.channel = channel.send(response.stdout)
                self.channel.send_exit_status(255)
                return True
        except Exception as e:
            self.logger.error(e)


class HoneyPot():
    """ HONEYPOT CLASS """
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = None
        self.conn = None
        self.family = socket.AF_INET
        self.type = socket.SOCK_STREAM
        self.level = socket.SOL_SOCKET
        self.optname = socket.SO_REUSEADDR
        self.transport = None
        self.event = threading.Event()
        self.hostkey = paramiko.RSAKey.generate(bits=3057)
        self.channel = None
        self.recv = []
        self.logger = setup_logger()

    def transport_paramiko(self, conn, addr):
        try:
            self.transport = paramiko.Transport(conn)
            self.transport.banner_timeout = 200
            self.transport.add_server_key(self.hostkey)
            self.transport.start_server(event=self.event,
                                        server=ServerParamiko()
                                        )
            self.channel = self.transport.accept(30)
        except SSHException:
            self.logger.error("SSH Negotiation failed")

    # def recv_data(self, conn, addr):
    #     with conn:
    #         print(f"Connected by {addr}")
    #         while True:
    #             data = conn.recv(4096)
    #             self.recv.append(data)
    #             if not data:
    #                 break

    def listen_socket(self):
        """ We need first to create our socket """
        self.conn = socket.socket(self.family, self.type)
        self.port = 20000
        val = 1
        self.conn.setsockopt(self.level, self.optname, val)
        self.conn.bind((self.host, self.port))
        self.conn.listen(5)
        self.logger.info("[*] SSH Server Listening on: %s:%s", self.host, self.port)
        while True:
            conn, addr = self.conn.accept()
            thread1 = threading.Thread(target=self.transport_paramiko,
                                       args=(conn, addr)
                                       )

            thread1.start()
            thread1.run()
            self.logger.info("[*] Accepting connections from: IP: %s:%s", addr[0], addr[1])


def main():
    """ INITIALIZE CLASS """
    honeypot = HoneyPot()
    try:
        honeypot.listen_socket()
    except KeyboardInterrupt:
        print("Keyboard interrupt maybe a CTRL+C or something else")
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
