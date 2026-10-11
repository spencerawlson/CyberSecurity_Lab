import json

from scanner import run_command


def search_exploits(product, version=""):
    """
    Query SearchSploit (Exploit-DB) for a product/version.

    Returns a list of exploit records. This is a passive,
    read-only lookup against the local Exploit-DB copy.
    """

    terms = [
        term
        for term in [product, version]
        if term
    ]

    if not terms:
        return []

    command = ["searchsploit", "--json", *terms]

    result = run_command(command)

    if not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)

    except json.JSONDecodeError:
        return []

    exploits = []

    for item in data.get("RESULTS_EXPLOIT", []):

        exploits.append({
            "title": item.get("Title", ""),
            "edb_id": item.get("EDB-ID", ""),
            "path": item.get("Path", ""),
        })

    return exploits


def enrich_with_exploits(target):
    """
    Attach Exploit-DB matches to each enumerated service
    that reported a product name.
    """

    for service in target.services:

        if service.product:
            service.exploits = search_exploits(
                service.product,
                service.version,
            )

    return target
