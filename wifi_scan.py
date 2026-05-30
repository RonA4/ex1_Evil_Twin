import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

"""
Implements the Network Discovery stage of the Evil Twin attack and defense tool.
Main responsibilities:
    - Scan nearby Wi-Fi networks using repeated iw scan commands.
    - Parse scan results and extract SSID, BSSID, channel, signal strength, and security type.
    - Convert Wi-Fi frequencies to channel numbers when needed.
    - Merge repeated scan results by BSSID.
    - Display discovered WLAN networks in a clear table for target selection.
"""

@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str
    channel: Optional[int] = None
    signal_dbm: Optional[int] = None
    security: str = "Unknown"
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # In this iw-scan version, this is not real packets.
    # It means: how many scan rounds saw this network.
    packets: int = 1


def run_command(command, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=check,
    )


def frequency_to_channel(freq: int) -> Optional[int]:
    """
    Convert Wi-Fi frequency in MHz to Wi-Fi channel.
    """
    if freq == 2484:
        return 14

    # 2.4 GHz
    if 2412 <= freq <= 2472:
        return int((freq - 2407) / 5)

    # 5 GHz
    if 5000 <= freq <= 5900:
        return int((freq - 5000) / 5)

    # 6 GHz rough mapping
    if 5955 <= freq <= 7115:
        return int((freq - 5950) / 5)

    return None


def prepare_interface_for_iw_scan(interface: str) -> None:
    """
    Prepare the interface for active scanning with 'iw scan'.

    Important:
    This scan method works in managed mode, not monitor mode.
    """
    print(f"[INFO] Preparing {interface} for active Wi-Fi scan...")

    subprocess.run(
        ["rfkill", "unblock", "wifi"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    subprocess.run(
        ["ip", "link", "set", interface, "down"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    subprocess.run(
        ["iw", "dev", interface, "set", "type", "managed"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    subprocess.run(
        ["ip", "link", "set", interface, "up"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    time.sleep(1)


def parse_bssid(line: str) -> Optional[str]:
    """
    Example:
    BSS 5c:53:c3:8f:f0:bd(on wlxe84e06aed7ca)
    """
    match = re.search(r"BSS\s+([0-9a-fA-F:]{17})", line)

    if match:
        return match.group(1).lower()

    return None


def parse_signal(line: str) -> Optional[int]:
    """
    Example:
    signal: -52.00 dBm
    """
    match = re.search(r"signal:\s*(-?\d+)", line)

    if match:
        return int(match.group(1))

    return None


def parse_channel_from_ds(line: str) -> Optional[int]:
    """
    Example:
    DS Parameter set: channel 6
    """
    match = re.search(r"channel\s+(\d+)", line)

    if match:
        return int(match.group(1))

    return None


def detect_security(block_lines) -> str:
    """
    Basic security detection from iw scan output.
    """
    text = "\n".join(block_lines)

    has_rsn = "RSN:" in text
    has_wpa = "WPA:" in text
    has_privacy = "Privacy" in text or "privacy" in text
    has_sae = "SAE" in text

    if has_rsn and has_sae:
        return "WPA3/WPA2 (RSN/SAE)"

    if has_rsn:
        return "WPA2/WPA3 (RSN)"

    if has_wpa:
        return "WPA/WPA2 Vendor IE"

    if has_privacy:
        return "WEP/Privacy"

    return "Open"


def parse_iw_scan_output(output: str) -> Dict[str, WiFiNetwork]:
    """
    Parse the output of:
    iw dev <interface> scan

    Returns networks keyed by BSSID.
    """
    networks: Dict[str, WiFiNetwork] = {}

    current_bssid = None
    current_lines = []

    def finish_current_block():
        nonlocal current_bssid, current_lines

        if not current_bssid or not current_lines:
            return

        ssid = "<hidden>"
        signal = None
        channel = None
        freq = None

        for line in current_lines:
            stripped = line.strip()

            if stripped.startswith("SSID:"):
                value = stripped.split("SSID:", 1)[1].strip()
                ssid = value if value else "<hidden>"

            elif stripped.startswith("signal:"):
                signal = parse_signal(stripped)

            elif stripped.startswith("freq:"):
                try:
                    freq = int(stripped.split("freq:", 1)[1].strip())
                except Exception:
                    freq = None

            elif "DS Parameter set:" in stripped:
                channel = parse_channel_from_ds(stripped)

        if channel is None and freq is not None:
            channel = frequency_to_channel(freq)

        security = detect_security(current_lines)

        networks[current_bssid] = WiFiNetwork(
            ssid=ssid,
            bssid=current_bssid,
            channel=channel,
            signal_dbm=signal,
            security=security,
            packets=1,
        )

    for line in output.splitlines():
        bssid = parse_bssid(line)

        if bssid:
            finish_current_block()
            current_bssid = bssid
            current_lines = [line]
        else:
            if current_bssid:
                current_lines.append(line)

    finish_current_block()

    return networks


def merge_scan_results(
    all_networks: Dict[str, WiFiNetwork],
    round_networks: Dict[str, WiFiNetwork],
) -> None:
    """
    Merge one scan round into the global result dictionary.
    """
    now = time.time()

    for bssid, net in round_networks.items():
        if bssid not in all_networks:
            net.first_seen = now
            net.last_seen = now
            net.packets = 1
            all_networks[bssid] = net

            print(
                f"[FOUND] SSID={net.ssid} "
                f"BSSID={net.bssid} "
                f"CH={net.channel} "
                f"SIGNAL={net.signal_dbm} "
                f"SECURITY={net.security}"
            )

        else:
            existing = all_networks[bssid]
            existing.last_seen = now
            existing.packets += 1

            if net.ssid and net.ssid != "<hidden>":
                existing.ssid = net.ssid

            if net.channel is not None:
                existing.channel = net.channel

            if net.signal_dbm is not None:
                existing.signal_dbm = net.signal_dbm

            if net.security and net.security != "Unknown":
                existing.security = net.security


def scan_networks(
    interface: str,
    duration: int = 60,
    hop_channels: bool = True,
) -> Dict[str, WiFiNetwork]:
    """
    Network Discovery stage.

    If the user chooses 60 seconds, this function keeps scanning
    for approximately 60 seconds.

    It repeatedly runs:
        iw dev <interface> scan

    This is used instead of Scapy passive monitor sniffing because
    this adapter/VirtualBox setup has monitor-mode capture problems.
    """
    if duration <= 0:
        duration = 60

    print(f"[INFO] Starting Wi-Fi network discovery on {interface}")
    print(f"[INFO] Requested scan duration: {duration} seconds")
    print("[INFO] Scan method: repeated iw scan")
    print("[INFO] Do not use monitor mode for this scan method.")

    prepare_interface_for_iw_scan(interface)

    all_networks: Dict[str, WiFiNetwork] = {}

    start_time = time.time()
    end_time = start_time + duration
    scan_round = 1

    while True:
        now = time.time()

        if now >= end_time:
            break

        remaining_before = max(0, int(end_time - now))

        print("\n" + "-" * 70)
        print(f"[SCAN] Round {scan_round}")
        print(f"[SCAN] Remaining time before this round: {remaining_before} seconds")
        print("-" * 70)

        result = run_command(["iw", "dev", interface, "scan"], check=False)

        if result.returncode != 0:
            print("[WARNING] iw scan failed in this round.")

            if result.stderr.strip():
                print(result.stderr.strip())

        else:
            round_networks = parse_iw_scan_output(result.stdout)
            print(f"[SCAN] Round {scan_round} found {len(round_networks)} network(s).")
            merge_scan_results(all_networks, round_networks)

        elapsed = int(time.time() - start_time)
        remaining_after = max(0, int(end_time - time.time()))

        print(f"[SCAN] Elapsed time: {elapsed} seconds")
        print(f"[SCAN] Remaining time after this round: {remaining_after} seconds")
        print(f"[SCAN] Unique networks so far: {len(all_networks)}")

        if remaining_after <= 0:
            break

        sleep_time = min(5, remaining_after)
        print(f"[SCAN] Waiting {sleep_time} seconds before next scan round...")
        time.sleep(sleep_time)

        scan_round += 1

    total_elapsed = int(time.time() - start_time)

    print("\n" + "=" * 70)
    print("[OK] Network discovery finished.")
    print(f"[OK] Actual scan time: {total_elapsed} seconds")
    print(f"[OK] Total unique networks found: {len(all_networks)}")
    print("=" * 70)

    return all_networks


def print_network_table(networks: Dict[str, WiFiNetwork]) -> None:
    """
    Print discovered networks in a table.
    """
    print("\n" + "=" * 110)
    print("DISCOVERED WLAN NETWORKS")
    print("=" * 110)
    print(
        f"{'ID':<4} "
        f"{'SSID':<25} "
        f"{'BSSID':<20} "
        f"{'CH':<5} "
        f"{'SIGNAL':<8} "
        f"{'SECURITY':<22} "
        f"{'SEEN':<6}"
    )
    print("-" * 110)

    if not networks:
        print("No networks found.")
    else:
        for idx, net in enumerate(networks.values(), start=1):
            print(
                f"{idx:<4} "
                f"{net.ssid[:24]:<25} "
                f"{net.bssid:<20} "
                f"{str(net.channel):<5} "
                f"{str(net.signal_dbm):<8} "
                f"{net.security[:21]:<22} "
                f"{net.packets:<6}"
            )

    print("=" * 110 + "\n")