import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap, sniff
from wifi_utils import set_channel

"""
Implements the Victim Identification stage of the Evil Twin attack tool.

Main responsibilities:
    - Switch the selected wireless interface to monitor mode.
    - Listen on the selected target network channel.
    - Passively sniff 802.11 frames using Scapy.
    - Identify active client/station MAC addresses related to the selected AP BSSID.
    - Filter out broadcast, multicast, and AP addresses.
    - Display discovered clients in a table for victim selection.

"""

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


DEBUG_FRAMES = False


@dataclass
class WiFiClient:
    mac: str
    target_bssid: str
    packets: int = 0
    last_signal_dbm: Optional[int] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    directions: Dict[str, int] = field(default_factory=dict)


@dataclass
class ObservedBSSID:
    bssid: str
    ssid: str = "<unknown>"
    packets: int = 0
    last_signal_dbm: Optional[int] = None
    last_seen: float = field(default_factory=time.time)


def run_command(command, check: bool = False):
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=check,
    )


def prepare_interface_for_monitor(interface: str) -> bool:
    """
    Network discovery uses iw scan in managed mode.
    Client discovery requires monitor mode, so we switch here automatically.
    """
    print(f"[INFO] Preparing {interface} for monitor-mode client discovery...")

    commands = [
        ["rfkill", "unblock", "wifi"],
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "type", "monitor"],
        ["ip", "link", "set", interface, "up"],
    ]

    for cmd in commands:
        result = run_command(cmd, check=False)

        if result.returncode != 0:
            print(f"[ERROR] Command failed: {' '.join(cmd)}")

            if result.stderr.strip():
                print(result.stderr.strip())

            print("[ERROR] Could not prepare monitor mode.")
            return False

    time.sleep(1)
    print(f"[OK] {interface} is now in monitor mode.")
    return True


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None

    return mac.lower()


def is_group_or_multicast_mac(mac: Optional[str]) -> bool:
    """
    In MAC addresses, if the least significant bit of the first byte is 1,
    it is a group/multicast address, not a normal client.
    """
    mac = normalize_mac(mac)

    if not mac:
        return True

    try:
        first_byte = int(mac.split(":")[0], 16)
        return (first_byte & 1) == 1
    except Exception:
        return True


def is_real_client_mac(mac: Optional[str], target_bssid: str) -> bool:
    """
    Keep only real unicast client MAC addresses.
    """
    mac = normalize_mac(mac)
    target_bssid = normalize_mac(target_bssid)

    if not mac:
        return False

    if mac == BROADCAST_MAC:
        return False

    if mac == target_bssid:
        return False

    if is_group_or_multicast_mac(mac):
        return False

    return True


def get_packet_signal(pkt) -> Optional[int]:
    if pkt.haslayer(RadioTap):
        signal = getattr(pkt[RadioTap], "dBm_AntSignal", None)

        if signal is not None:
            return int(signal)

    return None


def get_flags(pkt) -> Tuple[bool, bool]:
    """
    Return ToDS and FromDS flags.

    In Scapy:
    bit 0 = ToDS
    bit 1 = FromDS
    """
    fc = int(pkt[Dot11].FCfield)
    to_ds = bool(fc & 0x1)
    from_ds = bool(fc & 0x2)

    return to_ds, from_ds


def get_dot11_ssid(pkt) -> str:
    """
    Extract SSID from beacon/probe response if available.
    """
    elt = pkt.getlayer(Dot11Elt)

    while elt is not None:
        try:
            if int(elt.ID) == 0:
                raw = bytes(elt.info)

                if not raw:
                    return "<hidden>"

                return raw.decode("utf-8", errors="replace")
        except Exception:
            pass

        elt = elt.payload.getlayer(Dot11Elt)

    return "<unknown>"


def update_observed_bssid(
    observed_bssids: Dict[str, ObservedBSSID],
    bssid: Optional[str],
    ssid: str,
    signal: Optional[int],
) -> None:
    bssid = normalize_mac(bssid)

    if not bssid:
        return

    now = time.time()

    if bssid not in observed_bssids:
        observed_bssids[bssid] = ObservedBSSID(
            bssid=bssid,
            ssid=ssid,
            packets=1,
            last_signal_dbm=signal,
            last_seen=now,
        )
    else:
        item = observed_bssids[bssid]
        item.packets += 1
        item.last_seen = now

        if ssid and ssid != "<unknown>":
            item.ssid = ssid

        if signal is not None:
            item.last_signal_dbm = signal


def get_target_related_client(pkt, target_bssid: str):
    """
    Tolerant infrastructure-mode client detection.

    First tries exact infrastructure cases.
    Then falls back to:
    if target BSSID appears in addr1/addr2/addr3,
    return the other real unicast MAC as a client candidate.
    """
    if not pkt.haslayer(Dot11):
        return None, None

    target_bssid = normalize_mac(target_bssid)

    addr1 = normalize_mac(pkt[Dot11].addr1)
    addr2 = normalize_mac(pkt[Dot11].addr2)
    addr3 = normalize_mac(pkt[Dot11].addr3)

    frame_type = pkt[Dot11].type
    subtype = pkt[Dot11].subtype

    # Beacon / Probe Response identify APs, not client stations.
    if frame_type == 0 and subtype in (5, 8):
        return None, None

    addresses = [addr1, addr2, addr3]

    if target_bssid not in addresses:
        return None, None

    try:
        to_ds, from_ds = get_flags(pkt)
    except Exception:
        to_ds, from_ds = False, False

    # Data frame: Client -> AP
    # ToDS=1, FromDS=0
    # addr1 = BSSID/AP
    # addr2 = Client
    if frame_type == 2 and to_ds and not from_ds:
        if addr1 == target_bssid and is_real_client_mac(addr2, target_bssid):
            return addr2, "CLIENT -> AP"

    # Data frame: AP -> Client
    # ToDS=0, FromDS=1
    # addr1 = Client
    # addr2 = BSSID/AP
    if frame_type == 2 and from_ds and not to_ds:
        if addr2 == target_bssid and is_real_client_mac(addr1, target_bssid):
            return addr1, "AP -> CLIENT"

    # Management frames, common client -> AP cases.
    if frame_type == 0:
        if addr1 == target_bssid and is_real_client_mac(addr2, target_bssid):
            return addr2, "MGMT CLIENT -> AP"

        if addr3 == target_bssid and is_real_client_mac(addr2, target_bssid):
            return addr2, "MGMT RELATED"

    # Fallback:
    # If the target BSSID appears anywhere, pick another real unicast MAC.
    for candidate in addresses:
        if candidate == target_bssid:
            continue

        if is_real_client_mac(candidate, target_bssid):
            return candidate, "TARGET RELATED FALLBACK"

    return None, None


def print_observed_bssids(observed_bssids: Dict[str, ObservedBSSID]) -> None:
    print("\n" + "=" * 100)
    print("BSSIDS SEEN DURING CLIENT DISCOVERY")
    print("=" * 100)
    print(f"{'ID':<4} {'SSID':<25} {'BSSID':<20} {'SIGNAL':<8} {'PKTS':<8}")
    print("-" * 100)

    if not observed_bssids:
        print("No BSSIDs were observed.")
    else:
        sorted_items = sorted(
            observed_bssids.values(),
            key=lambda item: item.packets,
            reverse=True,
        )

        for idx, item in enumerate(sorted_items, start=1):
            print(
                f"{idx:<4} "
                f"{item.ssid[:24]:<25} "
                f"{item.bssid:<20} "
                f"{str(item.last_signal_dbm):<8} "
                f"{item.packets:<8}"
            )

    print("=" * 100 + "\n")


def discover_clients(
    interface: str,
    target_bssid: str,
    channel: int,
    duration: int = 60,
) -> Dict[str, WiFiClient]:
    """
    Discover active clients/stations related to the selected target BSSID.

    This requires monitor mode.
    """
    clients: Dict[str, WiFiClient] = {}
    observed_bssids: Dict[str, ObservedBSSID] = {}

    target_bssid = normalize_mac(target_bssid)

    print("\n[INFO] Starting passive client discovery")
    print(f"[INFO] Interface: {interface}")
    print(f"[INFO] Target BSSID: {target_bssid}")
    print(f"[INFO] Channel: {channel}")
    print(f"[INFO] Duration: {duration} seconds")

    monitor_ok = prepare_interface_for_monitor(interface)

    if not monitor_ok:
        print("[ERROR] Client discovery requires monitor mode.")
        print("[ERROR] The interface could not be switched to monitor mode.")
        return clients

    if channel is not None:
        ok = set_channel(interface, int(channel))

        if ok:
            print(f"[OK] Listening on target channel {channel}")
        else:
            print(f"[WARNING] Failed to set channel {channel}. Continuing anyway.")

    packet_count = 0
    target_related_count = 0
    target_bssid_seen = 0

    def handle_packet(pkt):
        nonlocal packet_count, target_related_count, target_bssid_seen

        if not pkt.haslayer(Dot11):
            return

        packet_count += 1

        addr1 = normalize_mac(pkt[Dot11].addr1)
        addr2 = normalize_mac(pkt[Dot11].addr2)
        addr3 = normalize_mac(pkt[Dot11].addr3)

        frame_type = pkt[Dot11].type
        subtype = pkt[Dot11].subtype
        signal = get_packet_signal(pkt)

        if DEBUG_FRAMES:
            print(
                "[DEBUG FRAME]",
                "type=", frame_type,
                "subtype=", subtype,
                "addr1=", addr1,
                "addr2=", addr2,
                "addr3=", addr3,
            )

        # Track APs seen in beacon/probe response.
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = get_dot11_ssid(pkt)
            bssid = addr2 or addr3
            update_observed_bssid(observed_bssids, bssid, ssid, signal)

        if target_bssid in (addr1, addr2, addr3):
            target_bssid_seen += 1

        client_mac, direction = get_target_related_client(pkt, target_bssid)

        if not client_mac:
            return

        target_related_count += 1
        now = time.time()

        if client_mac not in clients:
            clients[client_mac] = WiFiClient(
                mac=client_mac,
                target_bssid=target_bssid,
                packets=1,
                last_signal_dbm=signal,
                first_seen=now,
                last_seen=now,
                directions={direction: 1},
            )

            print(f"[CLIENT FOUND] {client_mac} | {direction} | signal={signal}")

        else:
            client = clients[client_mac]
            client.packets += 1
            client.last_seen = now

            if signal is not None:
                client.last_signal_dbm = signal

            client.directions[direction] = client.directions.get(direction, 0) + 1

    sniff(
        iface=interface,
        prn=handle_packet,
        timeout=duration,
        store=False,
    )

    print("\n[DEBUG] Client discovery statistics:")
    print(f"  Dot11 packets seen:          {packet_count}")
    print(f"  Target BSSID seen in frames: {target_bssid_seen}")
    print(f"  Target-related packets seen: {target_related_count}")
    print(f"  Unique real clients found:   {len(clients)}")

    if target_bssid_seen == 0:
        print("\n[WARNING] The selected target BSSID was not seen during this client scan.")
        print("[WARNING] This usually means one of these:")
        print("          1. The chosen BSSID is not active on this channel right now.")
        print("          2. The client is connected to another BSSID with the same SSID.")
        print("          3. The selected target is the Evil Twin AP, not the original AP.")
        print("          4. The channel/BSSID pair does not match.")

    if not clients:
        print_observed_bssids(observed_bssids)

    return clients


def print_clients_table(clients: Dict[str, WiFiClient]) -> None:
    print("\n" + "=" * 100)
    print("DISCOVERED CLIENTS / STATIONS")
    print("=" * 100)
    print(f"{'ID':<4} {'CLIENT MAC':<20} {'SIGNAL':<8} {'PKTS':<8} {'DIRECTIONS'}")
    print("-" * 100)

    if not clients:
        print("No real clients found for the selected target during this scan.")
    else:
        for idx, client in enumerate(clients.values(), start=1):
            directions_text = ", ".join(
                f"{name}:{count}" for name, count in client.directions.items()
            )

            print(
                f"{idx:<4} "
                f"{client.mac:<20} "
                f"{str(client.last_signal_dbm):<8} "
                f"{client.packets:<8} "
                f"{directions_text}"
            )

    print("=" * 100 + "\n")