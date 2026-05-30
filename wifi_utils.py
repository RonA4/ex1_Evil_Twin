import subprocess
import sys
from typing import List

"""
Provides common utility functions for the Evil Twin attack and defense tool.
Main responsibilities:
    - Run Linux system commands safely.
    - Verify that the tool is executed with root privileges.
    - Detect available wireless interfaces using iw.
    - Switch a Wi-Fi interface to monitor mode.
    - Set the Wi-Fi interface to a specific channel.
"""

def run_command(command: List[str], check: bool = True) -> subprocess.CompletedProcess:
    """
    Run a Linux command safely and return the result.
    """
    try:
        return subprocess.run(
            command,
            check=check,
            text=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] Command failed: {' '.join(command)}")
        print(exc.stderr.strip())
        raise


def require_root() -> None:
    """
    Scapy sniffing and interface changes usually require root.
    """
    result = subprocess.run(["id", "-u"], text=True, capture_output=True)
    if result.stdout.strip() != "0":
        print("[ERROR] Please run this tool with sudo:")
        print("sudo python3 main.py")
        sys.exit(1)


def show_wireless_interfaces() -> List[str]:
    """
    Return Wi-Fi interfaces detected by 'iw dev'.
    """
    result = run_command(["iw", "dev"], check=False)
    interfaces = []

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            iface = line.split("Interface ", 1)[1].strip()
            interfaces.append(iface)

    return interfaces


def set_monitor_mode(interface: str) -> None:
    """
    Put a Wi-Fi interface into monitor mode.
    """
    print(f"[INFO] Setting {interface} to monitor mode...")

    run_command(["ip", "link", "set", interface, "down"])
    run_command(["iw", "dev", interface, "set", "type", "monitor"])
    run_command(["ip", "link", "set", interface, "up"])

    print(f"[OK] {interface} is now in monitor mode.")


def set_channel(interface: str, channel: int) -> bool:
    """
    Set Wi-Fi channel. Returns True if successful.
    """
    result = run_command(
        ["iw", "dev", interface, "set", "channel", str(channel)],
        check=False,
    )

    if result.returncode != 0:
        return False

    return True