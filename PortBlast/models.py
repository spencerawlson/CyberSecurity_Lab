from dataclasses import dataclass, field, asdict


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""

    def dictionary(self):
        return asdict(self)


@dataclass
class Target:
    address: str
    hostname: str = ""
    services: list[Service] = field(default_factory=list)

    def dictionary(self):
        return {
            "address": self.address,
            "hostname": self.hostname,
            "services": [
                service.dictionary()
                for service in self.services
            ],
        }