"""
Forward secrecy demo for TLS 1.2 static RSA versus ECDHE.

This test intentionally starts two local TLS servers:

1. bad_static_rsa:
   TLS_RSA_WITH_AES_128_GCM_SHA256
   OpenSSL name: AES128-GCM-SHA256
   IANA hex: 0x009C

2. good_ecdhe:
   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
   OpenSSL name: ECDHE-RSA-AES128-GCM-SHA256
   IANA hex: 0xC02F

Both servers use the same RSA certificate and key. The test captures a request that
contains a fake Authorization header, then asks tshark to decrypt the pcap using
only the server private key.

Expected result:
- Static RSA traffic decrypts and exposes the fake bearer token.
- ECDHE traffic does not decrypt with only the server private key.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CERT = ROOT / "certs" / "server.crt"
KEY = ROOT / "certs" / "server.key"
PCAPS = ROOT / "pcaps"
TOKEN = "Bearer DEMO_TOKEN_IF_YOU_CAN_READ_THIS_TLS_WAS_DECRYPTED"


class ProcessError(RuntimeError):
    pass


def run(cmd: list[str], *, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise ProcessError(
            f"Command failed: {' '.join(cmd)}\n"
            f"returncode={proc.returncode}\n"
            f"stdout={proc.stdout}\n"
            f"stderr={proc.stderr}"
        )
    return proc


def wait_for_port(port: int, cipher: str) -> None:
    deadline = time.time() + 10
    last = ""
    while time.time() < deadline:
        proc = run(
            [
                "openssl",
                "s_client",
                "-connect",
                f"127.0.0.1:{port}",
                "-tls1_2",
                "-cipher",
                cipher,
                "-servername",
                "localhost",
                "-brief",
            ],
            timeout=5,
            check=False,
        )
        last = proc.stdout + proc.stderr
        if "Protocol version: TLSv1.2" in last and "Ciphersuite:" in last:
            return
        time.sleep(0.2)
    raise TimeoutError(f"TLS server on port {port} did not become ready. Last output:\n{last}")


@pytest.fixture(scope="session", autouse=True)
def ensure_cert() -> None:
    run([str(ROOT / "scripts" / "generate-cert.sh")])
    PCAPS.mkdir(exist_ok=True)


def start_tls_server(port: int, openssl_cipher: str) -> subprocess.Popen[str]:
    # @SECLEVEL=0 makes this lab robust across OpenSSL builds that otherwise
    # reject older key-exchange modes. This is intentionally a vulnerable lab.
    cipher_expr = f"{openssl_cipher}:@SECLEVEL=0"
    cmd = [
        "openssl",
        "s_server",
        "-accept",
        str(port),
        "-cert",
        str(CERT),
        "-key",
        str(KEY),
        "-www",
        "-tls1_2",
        "-cipher",
        cipher_expr,
        "-no_ticket",
    ]
    return subprocess.Popen(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )


def stop_process(proc: subprocess.Popen[str], *, sig: int = signal.SIGTERM) -> None:
    if proc.poll() is not None:
        return
    os.killpg(os.getpgid(proc.pid), sig)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait(timeout=5)


def capture_request(port: int, client_cipher: str, pcap: Path) -> None:
    if pcap.exists():
        pcap.unlink()

    tcpdump = subprocess.Popen(
        [
            "tcpdump",
            "-U",
            "-i",
            "lo",
            "-s",
            "0",
            "-w",
            str(pcap),
            f"tcp port {port}",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
    )
    try:
        time.sleep(0.8)
        run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--insecure",
                "--http1.1",
                "--tlsv1.2",
                "--tls-max",
                "1.2",
                "--ciphers",
                f"{client_cipher}:@SECLEVEL=0",
                "--header",
                f"Authorization: {TOKEN}",
                f"https://127.0.0.1:{port}/",
            ],
            timeout=20,
        )
        # Let tcpdump drain the kernel capture buffer before we interrupt it.
        time.sleep(1)
    finally:
        stop_process(tcpdump, sig=signal.SIGINT)

    if not pcap.exists() or pcap.stat().st_size == 0:
        raise AssertionError(f"No packets captured to {pcap}")


def decrypt_http_authorization_with_server_key(pcap: Path, port: int) -> str:
    # Wireshark/tshark can decrypt TLS 1.2 RSA key-transport sessions using the
    # server private key. It cannot decrypt ECDHE sessions from the cert key.
    # Format: ip,port,protocol,key_file,password
    keys_list = f"127.0.0.1,{port},http,{KEY},"
    proc = run(
        [
            "tshark",
            "-r",
            str(pcap),
            "-o",
            f"tls.keys_list:{keys_list}",
            "-Y",
            "http.authorization",
            "-T",
            "fields",
            "-e",
            "http.authorization",
        ],
        timeout=30,
        check=False,
    )
    return (proc.stdout + proc.stderr).strip()


def negotiated_cipher(port: int, cipher: str) -> str:
    proc = run(
        [
            "openssl",
            "s_client",
            "-connect",
            f"127.0.0.1:{port}",
            "-tls1_2",
            "-cipher",
            f"{cipher}:@SECLEVEL=0",
            "-servername",
            "localhost",
            "-brief",
        ],
        timeout=10,
    )
    return proc.stdout + proc.stderr


def run_case(name: str, port: int, cipher: str) -> str:
    server = start_tls_server(port, cipher)
    try:
        wait_for_port(port, f"{cipher}:@SECLEVEL=0")
        handshake = negotiated_cipher(port, cipher)
        assert "Protocol version: TLSv1.2" in handshake
        pcap = PCAPS / f"{name}.pcap"
        capture_request(port, cipher, pcap)
        return decrypt_http_authorization_with_server_key(pcap, port)
    finally:
        stop_process(server)


def test_static_rsa_tls12_can_be_decrypted_with_server_private_key() -> None:
    decrypted = run_case(
        name="bad_static_rsa_AES128_GCM_SHA256",
        port=9443,
        cipher="AES128-GCM-SHA256",
    )
    assert TOKEN in decrypted


def test_ecdhe_tls12_cannot_be_decrypted_with_only_server_private_key() -> None:
    decrypted = run_case(
        name="good_ecdhe_RSA_AES128_GCM_SHA256",
        port=9444,
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    assert TOKEN not in decrypted
