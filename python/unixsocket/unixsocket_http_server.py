#!/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from socketserver import UnixStreamServer

class UnixHTTPServer(UnixStreamServer):
  def get_request(self):
    request, client_address = self.socket.accept()
    # BaseHTTPRequestHandler expects a tuple with the client address at index
    # 0, so we fake one
    if len(client_address) == 0:
      client_address = (self.server_address,)
    return (request, client_address)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Respond with the file contents.
        self.send_response(200)
        self.end_headers()
        self.wfile.write("ABCDEFG1234567\n".encode())

# Use TCP
# Bind to the local address only.
# server_address = ('127.0.0.1', 7777)
# httpd = HTTPServer(server_address, Handler)
#httpd.serve_forever() 

# Use UNIX SOCKET
os.remove("mysocket.sock")
server = UnixHTTPServer('mysocket.sock', Handler)
server.serve_forever()
