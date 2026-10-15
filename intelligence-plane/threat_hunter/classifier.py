import re
from typing import Dict, Any

class MitreThreatClassifier:
    """
    Inspects raw network telemetry, HTTP payloads, and Linux auditd syscalls.
    Maps malicious patterns and behavioral Z-score anomalies to MITRE ATT&CK tactics
    and computes a deterministic threat severity score (0.0 - 10.0).
    """

    def evaluate_telemetry(self, source_ip: str, target_service: str,
                           payload: str, requests_per_sec: int) -> Dict[str, Any]:
        upper_payload = payload.upper()
        mitre_tactic = "NONE"
        threat_score = 0.5
        soar_action = "ALLOW_TRAFFIC"
        deception_reroute = False

        # 1. MITRE T1190: Exploit Public-Facing Application (SQLi / JNDI / Path Traversal)
        if any(sig in upper_payload for sig in ("UNION SELECT", "OR 1=1", "${JNDI:", "../ETC/PASSWD", "<SCRIPT>")):
            mitre_tactic = "T1190_EXPLOIT_PUBLIC_APP"
            threat_score = 9.4
            soar_action = "REROUTE_TO_DECEPTION_HONEYPOT"
            deception_reroute = True

        # 2. MITRE T1059: Command and Scripting Execution / Container Escape
        elif any(sig in upper_payload for sig in ("/BIN/BASH", "NC -E", "CURL HTTP", "CHMOD +X", "DOCKER.SOCK")):
            mitre_tactic = "T1059_COMMAND_SHELL_EXEC"
            threat_score = 9.8
            soar_action = "CORDON_NODE_AND_ISOLATE_IP"
            deception_reroute = True

        # 3. MITRE T1498: Network Denial of Service (High-Velocity Volumetric Anomaly)
        elif requests_per_sec > 500:
            mitre_tactic = "T1498_NETWORK_DOS_FLOOD"
            threat_score = min(10.0, round(6.5 + (requests_per_sec / 500.0), 2))
            soar_action = "RATE_LIMIT_AND_BLACKLIST_IP"

        # 4. MITRE T1110: Brute Force Credential Stuffing
        elif re.search(r"(FAILED_AUTH_BURST|INVALID_JWT_SIGNATURE)", upper_payload):
            mitre_tactic = "T1110_CREDENTIAL_BRUTE_FORCE"
            threat_score = 8.1
            soar_action = "REVOKE_TOKENS_AND_QUARANTINE_IP"

        return {
            "source_ip": source_ip,
            "target_service": target_service,
            "mitre_tactic_id": mitre_tactic,
            "threat_score": threat_score,
            "recommended_soar_action": soar_action,
            "reroute_to_honeypot": deception_reroute
        }
