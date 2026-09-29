import platform
import shutil


TOOLS = {
    "rustscan": "RustScan",
    "nmap": "Nmap",
    "searchsploit": "SearchSploit",
    "msfconsole": "Metasploit",
    "hydra": "Hydra",
    "john": "John the Ripper",
}


def detect_tools():
    results = {}

    for executable, display_name in TOOLS.items():
        path = shutil.which(executable)

        results[executable] = {
            "name": display_name,
            "available": path is not None,
            "path": path,
        }

    return results


def platform_info():
    return {
        "system": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
    }