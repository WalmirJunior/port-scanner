#!/usr/bin/env python3
"""
port_scanner.py

Scanner de portas TCP simples

Uso:
    python3 port_scanner.py -t 172.16.1.55 -p 1-1000
    python3 port_scanner.py -t 172.16.1.55 -p 22,80,443,1337
    python3 port_scanner.py -t 172.16.1.55 -p 1-65535 --threads 200 --banner
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_ports(port_arg: str) -> list[int]:
    ports: set[int] = set()
    for chunk in port_arg.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    invalid = [p for p in ports if not (0 < p < 65536)]
    if invalid:
        raise ValueError(f"Porta(s) fora do range válido (1-65535): {invalid}")

    return sorted(ports)


def grab_banner(sock: socket.socket, target: str) -> str:
    try:
        sock.settimeout(1.5)
        try:
            data = sock.recv(1024)
        except socket.timeout:
            data = b""

        if not data:
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            data = sock.recv(4096)

        return data.decode(errors="replace").strip().split("\n")[0][:120]
    except Exception:
        return ""


def scan_port(target: str, port: int, timeout: float, banner: bool) -> tuple[int, bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((target, port))
    is_open = result == 0

    banner_text = ""
    if is_open and banner:
        banner_text = grab_banner(s, target)

    s.close()
    return port, is_open, banner_text


def main():
    parser = argparse.ArgumentParser(description="Scanner de portas TCP simples")
    parser.add_argument("-t", "--target", required=True, help="IP ou hostname alvo")
    parser.add_argument(
        "-p", "--ports", required=True,
        help="Portas: '1-1000', '22,80,443' ou combinação"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Timeout por porta em segundos (default: 1.0)"
    )
    parser.add_argument(
        "--threads", type=int, default=100,
        help="Threads simultâneas (default: 100)"
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="Tentar ler banner/resposta do serviço em portas abertas"
    )
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Não foi possível resolver o host: {args.target}")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"[*] Alvo: {args.target} ({target_ip})")
    print(f"[*] Portas: {len(ports)} | Threads: {args.threads} | Timeout: {args.timeout}s\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, target_ip, port, args.timeout, args.banner): port
            for port in ports
        }
        for future in as_completed(futures):
            port, is_open, banner_text = future.result()
            if is_open:
                open_ports.append(port)
                line = f"[+] Porta {port} ABERTA"
                if banner_text:
                    line += f"  -> {banner_text}"
                print(line)

    print(f"\n[*] Scan finalizado. {len(open_ports)} porta(s) aberta(s): {sorted(open_ports)}")


if __name__ == "__main__":
    main()
