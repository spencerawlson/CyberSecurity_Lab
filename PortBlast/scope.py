import ipaddress
import json
from pathlib import Path


class ScopeError(Exception):
    pass


class Scope:
    def __init__(self, filename="scope.json"):
        base_dir = Path(__file__).resolve().parent
        path = base_dir / filename

        if not path.exists():
            raise ScopeError(
                f"Scope file not found: {path}"
            )

        try:
            with path.open(
                "r",
                encoding="utf-8-sig"
            ) as file:
                config = json.load(file)

        except json.JSONDecodeError as error:
            raise ScopeError(
                f"Invalid scope configuration: {error}"
            ) from error

        networks = config.get(
            "authorized_networks",
            []
        )

        if not networks:
            raise ScopeError(
                "No authorized networks configured."
            )

        try:
            self.networks = [
                ipaddress.ip_network(network)
                for network in networks
            ]

        except ValueError as error:
            raise ScopeError(
                f"Invalid network in scope.json: {error}"
            ) from error

    def validate(self, target: str):

        try:
            address = ipaddress.ip_address(target)

        except ValueError as error:
            raise ScopeError(
                "PortBlast requires an IP address "
                "as the target."
            ) from error

        for network in self.networks:

            if address in network:
                return address

        raise ScopeError(
            f"Target {target} is outside "
            "the authorized PortBlast scope."
        )