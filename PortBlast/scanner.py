import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from models import Service, Target


class ScannerError(Exception):
    pass


def run_command(command):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise ScannerError(
            f"Executable not found: {command[0]}"
        )


def rustscan(target):
    """
    Fast TCP discovery.

    Returns a sorted list of discovered ports.
    """

    command = [
        "rustscan",
        "-a",
        target,
        "--",
        "-Pn",
    ]

    result = run_command(command)

    ports = set()

    for line in result.stdout.splitlines():

        # Typical RustScan output:
        # Open 192.168.1.50:22

        if line.startswith("Open "):
            try:
                port = int(line.rsplit(":", 1)[1])
                ports.add(port)
            except (ValueError, IndexError):
                continue

    return sorted(ports)


def nmap_scan(target, ports=None):
    """
    Run Nmap service/version detection and return
    a normalized Target object.
    """

    with tempfile.NamedTemporaryFile(
        suffix=".xml",
        delete=False
    ) as temporary:

        xml_path = Path(temporary.name)

    command = [
        "nmap",
        "-Pn",
        "-sV",
        "-oX",
        str(xml_path),
    ]

    if ports:
        command.extend([
            "-p",
            ",".join(str(port) for port in ports)
        ])

    command.append(target)

    result = run_command(command)

    if result.returncode != 0:
        xml_path.unlink(missing_ok=True)

        raise ScannerError(
            result.stderr.strip()
            or "Nmap failed."
        )

    parsed = parse_nmap_xml(xml_path)

    xml_path.unlink(missing_ok=True)

    return parsed


def parse_nmap_xml(filename):
    tree = ET.parse(filename)
    root = tree.getroot()

    host = root.find("host")

    if host is None:
        raise ScannerError("No host information returned.")

    address_element = host.find("address")

    address = (
        address_element.attrib.get("addr", "")
        if address_element is not None
        else ""
    )

    target = Target(address=address)

    hostname = host.find("./hostnames/hostname")

    if hostname is not None:
        target.hostname = hostname.attrib.get("name", "")

    for port in host.findall("./ports/port"):

        state_element = port.find("state")
        service_element = port.find("service")

        state = ""

        if state_element is not None:
            state = state_element.attrib.get("state", "")

        if state != "open":
            continue

        service = Service(
            port=int(port.attrib["portid"]),
            protocol=port.attrib.get("protocol", "tcp"),
            state=state,
        )

        if service_element is not None:
            service.name = service_element.attrib.get(
                "name", ""
            )

            service.product = service_element.attrib.get(
                "product", ""
            )

            service.version = service_element.attrib.get(
                "version", ""
            )

            service.extra_info = service_element.attrib.get(
                "extrainfo", ""
            )

        target.services.append(service)

    return target