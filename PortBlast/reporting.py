import json
from datetime import datetime, timezone
from pathlib import Path


def write_report(target, directory="reports"):

    report_directory = Path(directory)

    report_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    filename = report_directory / (
        f"{target.address}_{timestamp}.json"
    )

    report = {
        "tool": "PortBlast",
        "version": "0.1.0",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "target": target.dictionary(),
    }

    with filename.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return filename