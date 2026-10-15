from threat_hunter.classifier import MitreThreatClassifier
from chaos_healer.operator import SelfHealingChaosOperator

def test_mitre_classifier_detects_sqli_and_reroutes_to_honeypot():
    classifier = MitreThreatClassifier()
    res = classifier.evaluate_telemetry(
        source_ip="185.220.101.44",
        target_service="payment-api",
        payload="GET /users?id=1' UNION SELECT username, password FROM admins--",
        requests_per_sec=12
    )
    assert res["mitre_tactic_id"] == "T1190_EXPLOIT_PUBLIC_APP"
    assert res["threat_score"] >= 9.0
    assert res["reroute_to_honeypot"] is True

def test_chaos_operator_cordons_and_replaces_compromised_node():
    operator = SelfHealingChaosOperator()
    res = operator.evaluate_and_heal_node(
        node_id="pod-telemetry-01",
        service_name="telemetry-collector",
        cpu_percent=45.0,
        compromised_flag=True
    )
    assert res["status"] == "CORDONED_AND_REPLACED"
    assert "clean-replica" in res["new_replica_id"]
