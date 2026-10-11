import argparse
import sys

from creds import hydra, john
from exploit import metasploit
from reporting import write_report
from scanner import (
    ScannerError,
    nmap_scan,
    rustscan,
)
from scope import Scope, ScopeError
from tools import detect_tools, platform_info
from vuln import enrich_with_exploits


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

    if tools["searchsploit"]["available"]:

        console.print()
        console.print(
            "[*] Searching Exploit-DB "
            "for discovered services..."
        )

        enrich_with_exploits(target)

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

        for item in service.exploits:
            console.print(
                f"    ! EDB-{item['edb_id']}: "
                f"{item['title']}"
            )

    report = write_report(target)

    console.print()
    console.print(
        f"[+] Report: {report}"
    )

    return 0


def parse_options(pairs):

    options = {}

    for pair in pairs or []:

        if "=" not in pair:
            raise ScannerError(
                "Invalid option (expected key=value): "
                f"{pair}"
            )

        key, value = pair.split("=", 1)
        options[key.strip()] = value.strip()

    return options


def crack_hashes(args):

    console = Console(args.silent)

    credentials = john(
        args.hash_file,
        hash_format=args.format,
        wordlist=args.wordlist,
    )

    console.print()
    console.print(f"PORTBLAST {VERSION}")
    console.print(f"Hash file: {args.hash_file}")
    console.print()

    if not credentials:
        console.print("[!] No hashes cracked.")
        return 0

    console.print("CRACKED CREDENTIALS")
    console.print("--------------------------------")

    for entry in credentials:
        console.print(
            f"{entry['username']:<16} "
            f"{entry['password']}"
        )

    return 0


def run_bruteforce(args):

    console = Console(args.silent)

    scope = Scope()

    target_address = str(
        scope.validate(args.target)
    )

    credentials = hydra(
        target_address,
        args.service,
        username=args.login,
        username_list=args.login_list,
        password=args.password,
        password_list=args.password_list,
    )

    console.print()
    console.print(f"PORTBLAST {VERSION}")
    console.print(
        f"Target: {target_address} "
        f"({args.service})"
    )
    console.print()

    if not credentials:
        console.print("[!] No credentials recovered.")
        return 0

    console.print("RECOVERED CREDENTIALS")
    console.print("--------------------------------")

    for entry in credentials:
        console.print(
            f"{entry['service']:<8} "
            f"{entry['login']:<16} "
            f"{entry['password']}"
        )

    return 0


def run_exploit(args):

    console = Console(args.silent)

    scope = Scope()

    target_address = str(
        scope.validate(args.target)
    )

    options = parse_options(args.option)

    console.print()
    console.print(f"PORTBLAST {VERSION}")
    console.print(f"Target : {target_address}")
    console.print(f"Module : {args.module}")
    console.print()

    output = metasploit(
        args.module,
        target_address,
        options,
    )

    console.print(output)

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

    crack_parser = subparsers.add_parser(
        "crack",
        help="Crack a local hash file with John the Ripper",
    )

    crack_parser.add_argument(
        "hash_file",
        help="Path to the hash file to crack",
    )

    crack_parser.add_argument(
        "--format",
        help="John hash format (e.g. raw-md5, nt)",
    )

    crack_parser.add_argument(
        "--wordlist",
        help="Wordlist to use",
    )

    crack_parser.add_argument(
        "--silent",
        action="store_true",
        help="Suppress console output",
    )

    bruteforce_parser = subparsers.add_parser(
        "bruteforce",
        help="Test credentials on an authorized service (Hydra)",
    )

    bruteforce_parser.add_argument(
        "target",
        help="Authorized target IP address",
    )

    bruteforce_parser.add_argument(
        "service",
        help="Hydra service module (e.g. ssh, ftp, http-get)",
    )

    bruteforce_parser.add_argument(
        "-l",
        "--login",
        help="Single username",
    )

    bruteforce_parser.add_argument(
        "-L",
        "--login-list",
        help="Username list file",
    )

    bruteforce_parser.add_argument(
        "-p",
        "--password",
        help="Single password",
    )

    bruteforce_parser.add_argument(
        "-P",
        "--password-list",
        help="Password list file",
    )

    bruteforce_parser.add_argument(
        "--silent",
        action="store_true",
        help="Suppress console output",
    )

    exploit_parser = subparsers.add_parser(
        "exploit",
        help="Run a Metasploit module against an authorized target",
    )

    exploit_parser.add_argument(
        "target",
        help="Authorized target IP address",
    )

    exploit_parser.add_argument(
        "--module",
        required=True,
        help="Metasploit module path",
    )

    exploit_parser.add_argument(
        "--option",
        action="append",
        metavar="KEY=VALUE",
        help="Module option (repeatable)",
    )

    exploit_parser.add_argument(
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

        if args.command == "crack":
            return crack_hashes(args)

        if args.command == "bruteforce":
            return run_bruteforce(args)

        if args.command == "exploit":
            return run_exploit(args)

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