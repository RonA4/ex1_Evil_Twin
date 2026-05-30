כן — תעתיקי את כל מה שבתיבה הזאת לקובץ בשם `README.md`:
# Evil Twin Attack and Defense Tool

## Course Information

**Course:** Wireless and Mobile Network Security  
**Assignment:** Assignment 1 - Evil Twin Attack  
**University:** Ariel University  
**Instructor:** Dr. Eyal Berliner  

---

## Group Members and Contributions

- **Ron Amsalem** 
- **Fadi**
We worked together.

---

## Project Overview

This project implements an Evil Twin attack and defense tool for an authorized wireless security laboratory environment.

The tool provides a single interactive command-line interface that guides the user through the full Evil Twin workflow:

1. Wireless network discovery
2. Target network selection
3. Victim/client identification
4. Evil Twin access point creation
5. Captive portal activation
6. Targeted disconnection
7. Credential capture
8. Evil Twin defense detection

The project also includes a defense mechanism that detects suspicious Evil Twin indicators, such as duplicate SSIDs, multiple BSSIDs, channel differences, security mismatches, and abnormal signal strength gaps.

This tool is intended strictly for an authorized academic lab environment.


## Project Structure

```text
evil_twin_project/
│
├── main.py
├── wifi_utils.py
├── wifi_scan.py
├── client_discovery.py
├── evil_twin_ap.py
├── captive_portal.py
├── targeted_disconnect.py
├── defense.py
│
├── configs/
│   ├── hostapd_evil_twin.conf
│   └── dnsmasq_evil_twin.conf
│
└── README.md
```

---

## File Descriptions

| File | Description |
|---|---|
| `main.py` | Main interactive menu and full attack/defense workflow orchestration. |
| `wifi_utils.py` | Utility functions for root checks, interface listing, monitor mode, and channel configuration. |
| `wifi_scan.py` | Network discovery using repeated `iw scan` commands. |
| `client_discovery.py` | Passive victim/client discovery using Scapy and monitor mode. |
| `evil_twin_ap.py` | Creates the Evil Twin AP using `hostapd` and `dnsmasq`. |
| `captive_portal.py` | Runs the HTTP captive portal and stores submitted demo credentials. |
| `targeted_disconnect.py` | Sends directed 802.11 deauthentication frames to the selected victim only. |
| `defense.py` | Detects possible Evil Twin candidates and provides recommended actions. |

---

## Hardware Requirements

The project requires Wi-Fi hardware that supports Linux wireless operations.

Recommended setup:

- Two  USB Wi-Fi adapters
- Monitor mode support
- Packet injection support
- One adapter for Evil Twin AP creation
- One adapter for scanning, client discovery, targeted disconnection, and defense detection
- Authorized lab client device, such as an iPad, smartphone, or laptop

The project was tested with two USB wireless adapters in a  DragonOS environment.

---

## Software Requirements

Required software:

- Python 3
- Scapy
- hostapd
- dnsmasq
- iw
- iproute2
- rfkill
- tcpdump


---

## Installation

Update the system and install required Linux packages:

```bash
sudo apt update
sudo apt install python3 python3-pip hostapd dnsmasq iw iproute2 rfkill tcpdump
```

Install Scapy:

```bash
pip3 install scapy
```

Verify that the wireless adapters are detected:

```bash
lsusb
iw dev
```

Optional Scapy verification:

```bash
python3 -c "from scapy.all import RadioTap, Dot11, Dot11ProbeReq; pkt=RadioTap()/Dot11()/Dot11ProbeReq(); pkt.show()"
```

---

## Running the Tool

Run the tool with root privileges:

```bash
sudo python3 main.py
```

Root privileges are required because the tool changes Wi-Fi interface modes, performs wireless scanning, uses monitor mode, and sends 802.11 frames.

---

## Main Menu Flow

The tool is operated from one interactive menu.

Typical full attack flow:

```text
1  -> Choose AP interface
3  -> Choose monitor interface
6  -> Network discovery - scan Wi-Fi networks
8  -> Choose target network
10 -> Discover clients on target network
12 -> Choose victim client
14 -> Start Evil Twin network
15 -> Start Captive Portal
16 -> Disconnect selected victim
17 -> Show captured credentials
18 -> Stop attack services
```

Typical defense flow:

```text
1  -> Choose AP interface
3  -> Choose monitor interface
6  -> Network discovery
8  -> Choose target network
14 -> Start Evil Twin network
6  -> Run network discovery again while Evil Twin is active
20 -> Run defense detection
18 -> Stop attack services
```

---

## Attack Stages

### 1. Network Discovery

The tool scans nearby WLAN networks using repeated `iw scan` commands. The scan results include:

- SSID
- BSSID
- Channel
- Signal strength
- Security type
- Number of times the network was observed

The scan duration can be selected by the user. For example, a 60-second scan repeats scan rounds until the requested time is reached.

---

### 2. Target Selection

After scanning, the tool displays all discovered networks in a numbered table. The user selects one target network from the list.

The selected target includes:

- SSID
- BSSID
- Channel
- Signal strength
- Security type

This information is used by the next stages of the attack.

---

### 3. Victim Identification

The tool switches the selected monitor interface into monitor mode and listens on the target network channel.

It passively sniffs 802.11 frames and identifies client devices related to the selected BSSID.

The user then selects one victim client MAC address from the discovered client list.

---

### 4. Evil Twin Network Creation

The tool creates a fake access point that imitates the selected target network.

It uses:

- `hostapd` to create the Wi-Fi access point
- `dnsmasq` to provide DHCP and DNS services

The tool automatically generates the required configuration files and starts the services.

---

### 5. Captive Portal

After the client connects to the Evil Twin network, the tool starts a local HTTP captive portal.

The portal displays a Wi-Fi verification login page and stores submitted demo credentials in:

```text
captured_credentials.jsonl
```

The portal also writes activity logs to:

```text
portal.log
```

---

### 6. Targeted Disconnection

The tool sends directed 802.11 deauthentication frames only between:

- The selected target AP BSSID
- The selected victim client MAC address

This demonstrates a targeted disconnection instead of a noisy broadcast attack against all nearby clients.

---

## Defense Mechanism

The defense module analyzes the latest Wi-Fi scan results and searches for Evil Twin indicators.

The tool groups detected APs by SSID and checks for:

- Same SSID with multiple BSSIDs
- Same SSID on different channels
- Same SSID with different security settings
- Large signal strength gap between APs with the same SSID
- Possible security downgrade

For each suspicious SSID group, the tool prints:

- Risk level
- Risk score
- Detection reasons
- Observed APs
- Recommended actions

The defense mechanism is heuristic. It detects suspicious candidates, not absolute proof of an attack.

---

## Recommended Defense Actions

When a suspicious SSID is detected, the tool recommends actions such as:

- Do not connect automatically to the suspicious SSID.
- Compare the observed BSSID with the known trusted AP BSSID.
- Check whether the security type changed unexpectedly.
- Inspect unusually strong signals.
- Verify with the network administrator in enterprise or mesh environments.

---

## Test Results

The following behavior was successfully demonstrated in the lab:

- Nearby WLAN networks were discovered.
- A target network was selected.
- An active victim client was identified.
- An Evil Twin AP was created.
- A client connected to the fake AP and received DHCP configuration.
- The captive portal displayed a login page.
- Demo credentials were captured and stored.
- Targeted disconnection was performed against the selected victim.
- The defense module detected the duplicated SSID as a possible Evil Twin candidate.

Screenshots and logs are included in the project report.


---

## Known Limitations

- The tool requires root privileges.
- Wireless behavior depends on Wi-Fi adapter and driver support.
- Some adapters support monitor mode but do not reliably support packet injection.
- WPA3 or Protected Management Frames may prevent deauthentication-based disconnection.
- Client discovery depends on live wireless traffic; quiet clients may not appear immediately.
- Captive portal pop-up behavior depends on the client operating system.
- HTTPS websites may not redirect cleanly because of certificate protections.
- Evil Twin defense detection is heuristic and may produce false positives in enterprise or mesh networks.
- In VirtualBox, USB Wi-Fi passthrough may require reconnecting the adapter if it becomes stuck.

---

### Network scan finds no networks

Reset the scanning adapter:

```bash
sudo rfkill unblock wifi
sudo ip link set <interface> down
sudo iw dev <interface> set type managed
sudo ip link set <interface> up
sudo iw dev <interface> scan
```

---


### Targeted disconnection sends frames but client does not disconnect

Possible reasons:

- WPA3 or PMF is enabled.
- The adapter does not support injection reliably.
- The selected BSSID or victim MAC is not the active one.
- The client reconnects very quickly.
- More rounds may be required in the lab test.


---

````
