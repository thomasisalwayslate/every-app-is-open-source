"""Byte relay to one already-prepared run-local engine; no file-read tool."""
import select
import socket
import sys

with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
    connection.connect(sys.argv[1])
    sources=[connection,sys.stdin.buffer]
    while True:
        readable,_,_=select.select(sources,[],[])
        for source in readable:
            if source is connection:
                data=connection.recv(65536)
                if not data:sys.exit(0)
                sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
            else:
                data=source.read1(65536)
                if not data:sys.exit(0)
                connection.sendall(data)
