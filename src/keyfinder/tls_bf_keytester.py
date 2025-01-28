"""
See TsharkKeyTester docstring
"""

import logging
import os
import subprocess
from tempfile import NamedTemporaryFile

LOGGER = logging.getLogger(__name__)


class TlsBfKeyTester():
    """
    This module implements a TLS session key brute force based on a custom tls-bf binary
    """
    def __init__(
            self,
            dump_file: str,
            tls_version: str,
            tls_ports: str = "443,8443"
        ) -> None:
        """
        tls-bf will only try to decrypt TLS for packets with dport in tls_ports
        tls_version: "TLS12", "TLS13" or "QUIC"
        """
        self.original_dump_file = dump_file
        assert tls_version in ("TLS12", "TLS13", "QUIC"), f"Bad TLS version '{tls_version}'"
        if tls_version != "TLS12":
            print(f"ERROR: version {tls_version} isn't supported yet")
        self.tls_version = tls_version
        self.tls_ports = tls_ports

        self.tls_bf = os.path.join("/usr/local/bin", "tls-bf")

        self.dump_file = NamedTemporaryFile(buffering=0, mode="wb")
        with open(self.original_dump_file, "rb") as fd:
            self.dump_file.write(fd.read())
        os.chown(self.dump_file.name, 65534, 65534)

    def close(self):
        """
        Delete temporary files
        """
        self.dump_file.close()

    def find_key(
            self,
            client_random: str,
            key_candidates_hex: list[str],
            tls_debug: bool = False) -> dict[str, bool|int|str] | None:
        """
        Find TLS key
        Return None if not found
        raise Exception on error
        """
        LOGGER.debug(
            "Checking %d keys (client random '%s') for %s",
            len(key_candidates_hex), client_random, self.original_dump_file
        )
        with NamedTemporaryFile(buffering=0) as keylog, \
                NamedTemporaryFile(mode="wb", buffering=0) as keys_fd:

            # Write a dummy keylog file to enable TLS decrypter in tshark
            os.chown(keylog.name, 65534, 65534)
            if self.tls_version == "TLS13" or self.tls_version == "QUIC":
                keylog.write(
                    (f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random} " + "0"*96 + "\n").encode("ascii")
                )
                keylog.write(
                    (f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random} " + "0"*96 + "\n").encode("ascii")
                )
                keylog.write(
                    (f"CLIENT_TRAFFIC_SECRET_0 {client_random} " + "0"*96 + "\n").encode("ascii")
                )
                keylog.write(
                    (f"SERVER_TRAFFIC_SECRET_0 {client_random} " + "0"*96 + "\n").encode("ascii")
                )
            else:  # self.tls_version == "TLS12"
                keylog.write(
                    (f"CLIENT_RANDOM {client_random} " + "0"*96 + "\n").encode("ascii")
                )

            # Write key candidates
            os.chown(keys_fd.name, 65534, 65534)
            for key in key_candidates_hex:
                keys_fd.write(key.encode())

            args = [
                self.tls_bf,
                client_random,
                keys_fd.name,
                self.dump_file.name,
                f"{self.tls_ports}"
            ]
            if tls_debug:
                # TODO: put a debug variable in environ when functionnality is implemented in tls-bf
                print("WARNING: tls_debug not supported yet")
            p = subprocess.run(
                args=args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=self.set_user,
                env={
                    **os.environ,
                    "HOME": "/nonexistent",
                    "USER": "nobody"
                }
            )

            if p.returncode != 0:
                LOGGER.error("tls-bf exited with code %s", p.returncode)
                LOGGER.debug("tls-bf stdout: %s", p.stdout.decode("utf-8"))
                LOGGER.debug("tls-bf stderr: %s", p.stderr.decode("utf-8"))
                raise Exception(f"tls-bf exited with code {p.returncode}")

            last_line = p.stdout.decode("utf-8").split("\n")[-2]
            if not last_line.startswith("Found key "):
                LOGGER.error(
                    "No brute force result in last line: Keys not found? Is traffic dump is incomplete?"
                )
                LOGGER.debug("tls-bf stdout: %s", p.stdout.decode("utf-8"))
                LOGGER.debug("tls-bf stderr: %s", p.stderr.decode("utf-8"))
                return {
                    "success": False
                }
            
            if self.tls_version == "TLS13" or self.tls_version == "QUIC":
                # TODO: not supported yet
                print("ERROR: TLS 1.3 isn't supported yet by tls-bf");
                exit(8)
                #client_key_position, client_secret_key, \
                #    server_key_position, server_secret_key = last_line.split("=")[1].split(";")
                #return {
                #    "success": True,
                #    "client_key_position": int(client_key_position),
                #    "client_secret_key": client_secret_key,
                #    "server_key_position": int(server_key_position),
                #    "server_secret_key": server_secret_key
                #}
            elif self.tls_version == "TLS12":
                master_key = last_line.split(" ")[2]
                return {
                    "success": True,
                    "master_key": master_key
                }


    @staticmethod
    def set_user():
        """
        It's bad to run complex code like TLS decryption as root
        """
        os.setgid(65534)
        os.setuid(65534)


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)

    keytester = TlsBfKeyTester(
        dump_file="tests/resources/tls1.2/dump1.pcap",
        tls_version="TLS12"
    )
    try:
        # 4f325... is the good key
        good = keytester.find_key(
            client_random="af687dbf4004cea24074bb94fa93da4e1e8b3dbf6826ed5ba898ee7cc393d1dd",
            key_candidates_hex=[
                "3f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777",
                "4f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777",
                "5f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777"
            ]
        )
        print(json.dumps(good, indent=4))

        bad = keytester.find_key(
            client_random="af687dbf4004cea24074bb94fa93da4e1e8b3dbf6826ed5ba898ee7cc393d1dd",
            key_candidates_hex=[
                "7f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777",
                "8f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777",
                "9f325075443842be887367b14b464642117ca7555c6aa5af85b3f2f2f920e2e67da8225d329c611c3fe4c18d8c9f9777"
            ]
        )
        print(json.dumps(bad, indent=4))

    finally:
        keytester.close()

