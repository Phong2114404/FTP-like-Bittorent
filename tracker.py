import socket
import threading
import json
import math

PIECE_SIZE = 1024*1024
class Tracker:
    def __init__(self, host='10.0.235.147', port=9999):
        self.host = host
        self.port = port
        self.peers = {}  # Dictionary to hold peer information

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Tracker running on {self.host}:{self.port}")
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()

    def handle_client(self, client_socket, addr):
        try:
            while True:
                data = client_socket.recv(1024*1024)
                if not data:
                    break
                data = json.loads(data.decode())
                command = data['command']

                if command == 'register':

                    pieces = []
                    for size in data['sizes']:
                        temp = math.ceil(size/PIECE_SIZE)
                        pieces.append(temp)

                    self.peers[addr] = {
                        'files': data['files'],
                        'ip': data['ip'],
                        'port': data['port'],
                        'sizes': data['sizes'],
                        'hashes': data['hashes'],
                        'pieces': pieces
                    }
                    print(f"Registered {addr} with files: {data['files']}, IP: {data['ip']}, Port: {data['port']}")
                elif command == 'request':
                    filename = data['file']

                    available_peers = [
                        {
                            'ip': peer_info['ip'],
                            'port': peer_info['port'],
                            'file': filename,
                            'size': peer_info['sizes'][peer_info['files'].index(filename)],
                            'hash': peer_info['hashes'][peer_info['files'].index(filename)],
                            'pieces': peer_info['pieces'][peer_info['files'].index(filename)]
                        }
                        for peer_addr, peer_info in self.peers.items() if filename in peer_info['files']
                    ]
                    response = json.dumps({"peers": available_peers}).encode()
                    client_socket.send(response)
        finally:
            client_socket.close()


if __name__ == "__main__":
    tracker = Tracker()
    tracker.start_server()

