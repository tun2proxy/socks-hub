#!/usr/bin/env python3

from smoke_socks5 import smoke_udp_chain


def main() -> int:
    data = smoke_udp_chain()
    print(f"udp smoke ok: {data.decode('utf-8')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())