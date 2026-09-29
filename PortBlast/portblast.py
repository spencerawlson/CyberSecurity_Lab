import argparse
import sys

from reporting import write_report
from scanner import (
    ScannerError,
    nmap_scan,
    rustscan,
)
from scope import Scope, ScopeError
from tools import detect_tools, platform_info


VERSION = "0.1.0"


class Console:
    def __init__(self, silent=False):
        self.silent = silent

    def print(self, message=""):
        if not self.silent:
            print(message)


def show_tools():

    info = platform_info()
    tools = detect_tools()

    print(f"PortBlast {VERSION}")
    print()
    print(f"Platform : {info['system']} {info['release']}")
    print(f"Python   : {info['python']}")
    print()

    print("Tool             Status")
    print("--------------------------------")

    for tool in tools.values():

        status = (
            f"FOUND ({tool['path']})"
            if tool["available"]
            else "NOT FOUND"
        )

        print(
            f"{tool['name']:<16} {status}"
        )


def scan_target(target_address, silent=False):

    console = Console(silent)

    scope = Scope()

    target_address = str(
        scope.validate(target_address)
    )

    tools = detect_tools()

    console.print()
    console.print(
        f"PORTBLAST {VERSION}"
    )

    console.print(
        f"Target: {target_address}"
    )

    console.print()

    ports = []

    if tools["rustscan"]["available"]:

        console.print(
            "[*] Running RustScan discovery..."
        )

        ports = rustscan(target_address)

        console.print(
            f"[+] Discovered {len(ports)} ports."
        )

    else:

        console.print(
            "[!] RustScan unavailable."
        )

        console.print(
            "[*] Falling back to Nmap."
        )

    if not tools["nmap"]["available"]:
        raise ScannerError(
            "Nmap is required for service enumeration."
        )

    console.print(
        "[*] Running Nmap service enumeration..."
    )

    target = nmap_scan(
        target_address,
        ports or None
    )

    console.print()
    console.print("OPEN SERVICES")
    console.print("--------------------------------")

    for service in target.services:

        description = " ".join(
            item
            for item in [
                service.product,
                service.version,
                service.extra_info,
            ]
            if item
        )

        console.print(
            f"{service.port}/{service.protocol:<5} "
            f"{service.name:<12} "
            f"{description}"
        )

    report = write_report(target)

    console.print()
    console.print(
        f"[+] Report: {report}"
    )

    return 0


def main():

    parser = argparse.ArgumentParser(
        prog="portblast",
        description=(
            "PortBlast authorized security "
            "assessment framework"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"PortBlast {VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    subparsers.add_parser(
        "tools",
        help="Detect installed security tools",
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan an authorized target",
    )

    scan_parser.add_argument(
        "target",
        help="Authorized target IP address",
    )

    scan_parser.add_argument(
        "--silent",
        action="store_true",
        help="Suppress console output",
    )

    args = parser.parse_args()

    try:

        if args.command == "tools":
            show_tools()
            return 0

        if args.command == "scan":
            return scan_target(
                args.target,
                args.silent,
            )

        parser.print_help()
        return 0

    except (
        ScopeError,
        ScannerError,
    ) as error:

        if not getattr(
            args,
            "silent",
            False
        ):
            print(
                f"[!] {error}",
                file=sys.stderr
            )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())