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
from dotenv import load_dotenv

load_dotenv()

HOST = "127.0.0.1"
PORT = 10000
event = threading.Event()
HOSTKEY = paramiko.RSAKey.generate(bits=3072)
message = "It SAUL GOOOOOD MAN"


class ValidatePassword():
    """ Password Validator """
    def __init__(self, password: str):
        self.password = password

    def is_upper(self):
        """ Validates if a password has upper case """
        for c in self.password:
            is_upper = [c for c in self.password.isupper()]
            if is_upper:
                print(f"Password has upper case: {message}")
            else:
                print("Password must have upper case")

    def is_lower(self):
        """ Validates if a password has lower case """
        for c in self.password:
            is_lower = [c for c in self.password.lower()]
            if is_lower:
                print(f"Password has lower case: {message}")
            else:
                print("Password must have lower case")

    def has_symbols(self):
        """ Validates if a password has symbols"""
        for c in self.password:
            if r'[^\w\s]' in c:
                print(f"Password has symbols: {message}")
            else:
                print("Password must have symbols")

    def has_digits(self):
        """ Validates if a password has digits """
        for c in self.password():
            has_digits = [c for c in self.password.isdigit()]
            if has_digits:
                print("Password has digits")
            else:
                print("Password need at least 1 digit")


class ServerParamiko(paramiko.ServerInterface):
    """ SERVER PARAMIKO """
    def __init__(self):
        pass

    def get_allowed_auths(self, username):
        return super().get_allowed_auths(username)

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
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_channel_request(self, kind, chanid) -> int:
        if kind == 'session':
            return OPEN_SUCCEEDED or 0
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_exec_request(self, channel, cmd):
        response = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        channel.send(response.stdout)
        channel.send_exit_status(255)
        return True


class HoneyPot():
    """ HONEYPOT CLASS """
    def __init__(self):
        pass

    def listen_socket(self):
        """ We nee first to create our socket """
        fd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        val = 1
        fd_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, val)
        fd_socket.bind((HOST, PORT))
        fd_socket.listen(5)
        print(f""" [*] SSH Server Listening on: {HOST}:{PORT}""")
        return fd_socket

    def accept_connections_and_set_server(self):
        """ FUNCTION ACCEPTS CONNECTION AND SET PARAMIKO SERVER """
        while True:
            conn, addr = self.listen_socket().accept()
            print(f"""
                  [*] Accepting connections from:
                  IP: {addr[0]}:{addr[1]} """)
            # Then when we can start to accept connections and do Transport
            try:
                t = paramiko.Transport(conn)
                t.banner_timeout = 200
                t.add_server_key(HOSTKEY)
                t.start_server(event=event, server=ServerParamiko())
                channel = t.accept(30)
                if channel is None:
                    print("There is NONE request auth")
                    exit(1)
                channel.send(b"Now you are in!")
            except SSHException:
                print("SSH Negotiation failed")


def main():
    """ INITIALIZE CLASS """
    honeypot = HoneyPot()
    honeypot.listen_socket()
    honeypot.accept_connections_and_set_server()


if __name__ == "__main__":
    main()
