from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from wifi_scan import WiFiNetwork

"""
Implements the Evil Twin defense detection mechanism.
Main responsibilities:
    - Analyze the latest Wi-Fi network scan results.
    - Group detected access points by SSID.
    - Detect suspicious Evil Twin indicators such as multiple BSSIDs,
      channel differences, security mismatches, and large signal gaps.
    - Calculate a risk score and risk level for each suspicious SSID group.
    - Print a detailed defense report with reasons, observed APs, and
      recommended user actions.
"""

@dataclass
class DefenseFinding:
    ssid: str
    risk_score: int
    risk_level: str
    reasons: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    networks: List[WiFiNetwork] = field(default_factory=list)


def normalize_value(value) -> str:
    if value is None:
        return "Unknown"
    return str(value)


def signal_gap_dbm(networks: List[WiFiNetwork]) -> Optional[int]:
    signals = [
        net.signal_dbm
        for net in networks
        if net.signal_dbm is not None
    ]

    if len(signals) < 2:
        return None

    return max(signals) - min(signals)


def risk_level_from_score(score: int) -> str:
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def build_recommended_actions(
    reasons: List[str],
    networks: List[WiFiNetwork],
    risk_level: str,
) -> List[str]:
    """
    Build user-facing recommended actions for suspicious Evil Twin indicators.

    The goal is not to block traffic automatically, but to guide the user
    toward safer manual verification.
    """
    actions = []

    actions.append("Do not connect automatically to this SSID until it is verified.")
    actions.append("Compare the observed BSSID with the known trusted AP BSSID.")

    reason_text = " ".join(reasons).lower()
    security_values = {normalize_value(net.security) for net in networks}
    channel_values = {normalize_value(net.channel) for net in networks}

    if "security" in reason_text or any("Open" in sec for sec in security_values):
        actions.append("Check for security downgrade, such as an Open network replacing a secured one.")

    if len(channel_values) > 1:
        actions.append("Verify whether the channel change is expected for the legitimate network.")

    if "signal" in reason_text:
        actions.append("Inspect the AP with unusually strong signal, especially if it appeared recently.")

    if risk_level in ("MEDIUM", "HIGH"):
        actions.append("Prefer disconnecting from the suspicious SSID until the legitimate AP is confirmed.")

    actions.append("If this is an enterprise or mesh network, verify with the network administrator.")

    return actions


def analyze_ssid_group(ssid: str, networks: List[WiFiNetwork]) -> Optional[DefenseFinding]:
    """
    Analyze all APs that advertise the same SSID.

    Evil Twin indicators:
    - Same SSID with multiple BSSIDs
    - Same SSID with different security types
    - Same SSID on different channels
    - Suspicious signal strength gap
    - Security downgrade
    """
    if ssid == "<hidden>":
        return None

    if len(networks) < 2:
        return None

    bssids = {normalize_value(net.bssid) for net in networks}
    securities = {normalize_value(net.security) for net in networks}
    channels = {normalize_value(net.channel) for net in networks}

    reasons = []
    score = 0

    if len(bssids) > 1:
        reasons.append("same SSID appears with multiple BSSIDs")
        score += 2

    if len(securities) > 1:
        reasons.append("same SSID appears with different security types")
        score += 2

    if len(channels) > 1:
        reasons.append("same SSID appears on different channels")
        score += 1

    security_text = " ".join(securities).lower()

    if "open" in security_text and ("wpa" in security_text or "rsn" in security_text):
        reasons.append("possible security downgrade: Open network appears next to secured network")
        score += 3

    gap = signal_gap_dbm(networks)

    if gap is not None and gap >= 25:
        reasons.append(f"large signal strength gap between APs with same SSID: {gap} dBm")
        score += 1

    if not reasons:
        return None

    risk_level = risk_level_from_score(score)

    recommended_actions = build_recommended_actions(
        reasons=reasons,
        networks=networks,
        risk_level=risk_level,
    )

    return DefenseFinding(
        ssid=ssid,
        risk_score=score,
        risk_level=risk_level,
        reasons=reasons,
        recommended_actions=recommended_actions,
        networks=networks,
    )


def detect_possible_evil_twins(networks: Dict[str, WiFiNetwork]) -> List[DefenseFinding]:
    """
    Detect suspicious Evil Twin candidates from a Wi-Fi scan result.

    This is a heuristic defense mechanism. It does not prove an attack,
    but it highlights suspicious SSID groups that should be inspected.
    """
    by_ssid = defaultdict(list)

    for net in networks.values():
        if not net.ssid:
            continue

        if net.ssid == "<hidden>":
            continue

        by_ssid[net.ssid].append(net)

    findings = []

    for ssid, ssid_networks in by_ssid.items():
        finding = analyze_ssid_group(ssid, ssid_networks)

        if finding is not None:
            findings.append(finding)

    findings.sort(key=lambda item: item.risk_score, reverse=True)
    return findings


def print_networks_for_finding(networks: List[WiFiNetwork]) -> None:
    sorted_networks = sorted(
        networks,
        key=lambda net: net.signal_dbm if net.signal_dbm is not None else -999,
        reverse=True,
    )

    print(
        f"{'SSID':<25} "
        f"{'BSSID':<20} "
        f"{'CH':<6} "
        f"{'SIGNAL':<8} "
        f"{'SECURITY':<24} "
        f"{'SEEN':<6}"
    )
    print("-" * 100)

    for net in sorted_networks:
        print(
            f"{net.ssid[:24]:<25} "
            f"{str(net.bssid):<20} "
            f"{str(net.channel):<6} "
            f"{str(net.signal_dbm):<8} "
            f"{str(net.security)[:23]:<24} "
            f"{str(net.packets):<6}"
        )


def print_defense_report(networks: Dict[str, WiFiNetwork]) -> None:
    print("\n" + "=" * 100)
    print("DEFENSE REPORT - EVIL TWIN DETECTION")
    print("=" * 100)

    if not networks:
        print("[ERROR] No scan results available.")
        print("[INFO] Run Network Discovery first, then run defense detection.")
        print("=" * 100 + "\n")
        return

    findings = detect_possible_evil_twins(networks)

    print(f"[INFO] Total networks in scan: {len(networks)}")
    print(f"[INFO] Suspicious SSID groups found: {len(findings)}")
    print("-" * 100)

    if not findings:
        print("[OK] No obvious Evil Twin indicators were found in this scan.")
        print("[NOTE] This does not prove that the environment is safe.")
        print("[NOTE] It only means that no duplicate/suspicious SSID pattern was detected.")
        print("=" * 100 + "\n")
        return

    for idx, finding in enumerate(findings, start=1):
        print(f"\n[{idx}] Possible Evil Twin Candidate")
        print("=" * 100)
        print(f"SSID:        {finding.ssid}")
        print(f"Risk level:  {finding.risk_level}")
        print(f"Risk score:  {finding.risk_score}")

        print("\nReasons:")
        for reason in finding.reasons:
            print(f"  - {reason}")

        print("\nAPs observed with this SSID:")
        print_networks_for_finding(finding.networks)

        print("\nRecommended actions:")
        for action in finding.recommended_actions:
            print(f"  - {action}")

        print("\nInterpretation:")
        print(
            "  This SSID appears in a suspicious way. "
            "The same network name is advertised by multiple access points "
            "or with inconsistent wireless properties. "
            "This can indicate an Evil Twin candidate, but it may also happen "
            "in legitimate multi-AP networks."
        )

    print("\n" + "=" * 100)
    print("DEFENSE SUMMARY")
    print("=" * 100)
    print("[WARNING] The report identifies suspicious candidates, not final proof of an attack.")
    print("[INFO] To confirm an Evil Twin, compare BSSID, channel, security type, and signal behavior.")
    print("[INFO] Recommended actions are advisory and do not automatically block network activity.")
    print("=" * 100 + "\n")