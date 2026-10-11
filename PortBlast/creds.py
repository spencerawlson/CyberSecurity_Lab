import re
from pathlib import Path

from scanner import ScannerError, run_command


HYDRA_LINE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+"
    r"host:\s*(?P<host>\S+)\s+"
    r"login:\s*(?P<login>\S+)\s+"
    r"password:\s*(?P<password>\S+)"
)


def hydra(
    target,
    service,
    username=None,
    username_list=None,
    password=None,
    password_list=None,
):
    """
    Run Hydra against a single authorized service and return
    any recovered credentials.

    The caller is responsible for validating the target
    against the PortBlast scope before invoking this.
    """

    if not (username or username_list):
        raise ScannerError(
            "Hydra needs a username (-l) or "
            "a username list (-L)."
        )

    if not (password or password_list):
        raise ScannerError(
            "Hydra needs a password (-p) or "
            "a password list (-P)."
        )

    if username_list and not Path(username_list).exists():
        raise ScannerError(
            f"Username list not found: {username_list}"
        )

    if password_list and not Path(password_list).exists():
        raise ScannerError(
            f"Password list not found: {password_list}"
        )

    command = ["hydra"]

    if username:
        command.extend(["-l", username])
    else:
        command.extend(["-L", username_list])

    if password:
        command.extend(["-p", password])
    else:
        command.extend(["-P", password_list])

    command.extend([target, service])

    result = run_command(command)

    credentials = []

    for line in result.stdout.splitlines():

        match = HYDRA_LINE.search(line)

        if match:
            credentials.append({
                "port": int(match.group("port")),
                "service": match.group("service"),
                "login": match.group("login"),
                "password": match.group("password"),
            })

    return credentials


def john(hash_file, hash_format=None, wordlist=None):
    """
    Crack a local hash file with John the Ripper and return
    the recovered credentials.

    Operates only on a local file; it performs no network
    activity, so it is not scope-gated.
    """

    path = Path(hash_file)

    if not path.exists():
        raise ScannerError(
            f"Hash file not found: {hash_file}"
        )

    if wordlist and not Path(wordlist).exists():
        raise ScannerError(
            f"Wordlist not found: {wordlist}"
        )

    crack_command = ["john"]

    if hash_format:
        crack_command.append(f"--format={hash_format}")

    if wordlist:
        crack_command.append(f"--wordlist={wordlist}")

    crack_command.append(str(path))

    run_command(crack_command)

    show_command = ["john", "--show"]

    if hash_format:
        show_command.append(f"--format={hash_format}")

    show_command.append(str(path))

    result = run_command(show_command)

    cracked = []

    for line in result.stdout.splitlines():

        line = line.strip()

        # Skip blank lines and the trailing summary
        # (e.g. "1 password hash cracked, 0 left").
        if not line or ":" not in line:
            continue

        if line.endswith("cracked") or line.endswith("left"):
            continue

        parts = line.split(":")

        cracked.append({
            "username": parts[0],
            "password": parts[1] if len(parts) > 1 else "",
        })

    return cracked
