#!/bin/env python
import sys
import ssl
import socket
import select
import errno
import collections

SOCK_STR = {}

def sock_to_str(sock):
    return "%s:%s" % sock.getpeername()

def process_sock_read(sock, queue):
    while True:
        try:
            buf = sock.recv(4096)
            #print "* recv, sock: %s, len: %s" % (SOCK_STR[sock], len(buf))
            if len(buf):
                queue.append(buf)
        except ssl.SSLError as e:
            if e.args[0] == ssl.SSL_ERROR_WANT_READ:
                break
            else:
                raise
        except socket.error as e:
            if e.args[0] == errno.EWOULDBLOCK: 
                break
            else:
                raise

def process_sock_write(sock, queue):
    while len(queue) > 0:
        try:
            n = sock.send(queue[0])
            #print "* send, sock: %s, len: %s" % (SOCK_STR[sock], n)
            if n < len(queue[0]):
                queue[0] = queue[0][n:]
            else:
                queue.popleft()
        except ssl.SSLError as e:
            if e.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                break
            else:
                raise
        except socket.error, e:
            if e.args[0] == errno.EWOULDBLOCK: 
                break
            else:
                raise e

def rdproxy(host1, port1, host2, port2):
    sock1 = socket.socket()
    sock2 = socket.socket()
    sock1 = ssl.wrap_socket(sock1, certfile="agent.cert", ca_certs="ca.pem",
        cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1)
    sock1.connect((host1, int(port1)))
    SOCK_STR[sock1] = sock_to_str(sock1)
    print "* Connected %s" % SOCK_STR[sock1]
    sock2.connect((host2, int(port2)))
    SOCK_STR[sock2] = sock_to_str(sock2)
    print "* Connected %s" % SOCK_STR[sock2]
    sock1.setblocking(0)
    sock2.setblocking(0)
    queue1 = collections.deque()
    queue2 = collections.deque()
    epoll = select.epoll()
    epoll.register(sock1.fileno(), select.EPOLLIN | select.EPOLLERR | select.EPOLLET)
    epoll.register(sock2.fileno(), select.EPOLLIN | select.EPOLLERR | select.EPOLLET)
    while True:
        for fileno, event in epoll.poll(timeout=1):
            if fileno == sock1.fileno():
                if event & select.EPOLLERR:
                    print "* error, sock: %s" % SOCK_STR[sock1]
                if event & select.EPOLLIN:
                    process_sock_read(sock1, queue1)
            elif fileno == sock2.fileno():
                if event & select.EPOLLERR:
                    print "* error, sock: %s" % SOCK_STR[sock2]
                if event & select.EPOLLIN:
                    process_sock_read(sock2, queue2)
        process_sock_write(sock2, queue1)
        process_sock_write(sock1, queue2)

if __name__ == "__main__":
    # python rdproxy.py 127.0.0.1 4489 192.168.56.10 3389
    print sys.argv
    rdproxy(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
