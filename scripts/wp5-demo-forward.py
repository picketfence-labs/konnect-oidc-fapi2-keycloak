#!/usr/bin/env python3
"""Loopback-only opaque TCP forward for the WP5 local demo."""

import argparse
import signal
import socket
import threading


class LocalForwarder:
    def __init__(self, listen_host, listen_port, target_host, target_port):
        if listen_host != "127.0.0.1" or target_host != "127.0.0.1":
            raise ValueError("WP5 demo forwarding is loopback-only")
        if listen_port != 8443 or target_port != 18443:
            raise ValueError("WP5 demo forwarding ports are fixed")
        self.listen = (listen_host, listen_port)
        self.target = (target_host, target_port)
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.listener = None

    def stop(self, *_):
        self.stopping.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        with self.lock:
            active = list(self.connections)
        for pair in active:
            for connection in pair:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    connection.close()
                except OSError:
                    pass

    def pump(self, source, destination):
        try:
            while not self.stopping.is_set():
                data = source.recv(65536)
                if not data:
                    break
                destination.sendall(data)
        except OSError:
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def handle(self, client):
        try:
            upstream = socket.create_connection(self.target, timeout=3)
            client.settimeout(None)
            upstream.settimeout(None)
        except OSError:
            client.close()
            return

        pair = (client, upstream)
        with self.lock:
            if self.stopping.is_set():
                for connection in pair:
                    connection.close()
                return
            self.connections.add(pair)

        threads = [
            threading.Thread(target=self.pump, args=(client, upstream), daemon=True),
            threading.Thread(target=self.pump, args=(upstream, client), daemon=True),
        ]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            for connection in pair:
                try:
                    connection.close()
                except OSError:
                    pass
            with self.lock:
                self.connections.discard(pair)

    def serve(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(self.listen)
        self.listener.listen(128)
        self.listener.settimeout(0.25)
        print("WP5 local TCP forward active", flush=True)
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stopping.is_set():
                    break
                raise
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()
        self.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", required=True, type=int)
    args = parser.parse_args()
    try:
        forwarder = LocalForwarder(
            args.listen_host,
            args.listen_port,
            args.target_host,
            args.target_port,
        )
    except ValueError as error:
        parser.error(str(error))
    signal.signal(signal.SIGINT, forwarder.stop)
    signal.signal(signal.SIGTERM, forwarder.stop)
    try:
        forwarder.serve()
    except OSError:
        print("WP5 local TCP forward could not bind or accept connections", flush=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
