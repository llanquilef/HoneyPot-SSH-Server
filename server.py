""" HONEYPOT WITH PARAMIKO AND SOCKET MODULE """
import socket
import os
import threading
import paramiko
from paramiko.ssh_exception import SSHException
from paramiko.common import AUTH_FAILED, AUTH_SUCCESSFUL

HOST = "127.0.0.1"
PORT = 10000
event = threading.Event()
HOSTKEY = paramiko.RSAKey.generate(bits=3072)


class ServerParamiko(paramiko.ServerInterface):
    """ SERVER PARAMIKO """
    def __init__(self):
        pass

    def get_allowed_auths(self, username):
        return super().get_allowed_auths(username)

    def check_auth_password(self, username: str, password: str):
        if username == os.environ.get('username') and password == os.environ.get('password'):
            return AUTH_SUCCESSFUL
        return AUTH_FAILED


class HoneyPot():
    """ HONEYPOT CLASS """
    def __init__(self):
        pass

    def create_socket(self):
        """ We nee first to create our socket """
        fd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        val = 1
        fd_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, val)
        fd_socket.bind((HOST, PORT))
        fd_socket.listen(5)
        print(f""" [*] SSH Server Listening on: {HOST}:{PORT}""")
        while True:
            conn, addr = fd_socket.accept()
            print(
                f"""
                [*] Accepting connections from:
                IP: {addr[0]}:{addr[1]}
                """)
            # Then when we can start to accept connections we can do Transport
            try:
                t = paramiko.Transport(conn)
                t.banner_timeout = 200
                t.add_server_key(HOSTKEY)
                t.start_server(event=event, server=ServerParamiko())
            except SSHException:
                print("SSH Negotiation failed")


def main():
    """ INITIALIZE CLASS """
    honeypot = HoneyPot()
    honeypot.create_socket()


if __name__ == "__main__":
    main()
