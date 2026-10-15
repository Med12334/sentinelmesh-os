from fastapi import FastAPI
from pydantic import BaseModel
from threat_hunter.classifier import MitreThreatClassifier
from chaos_healer.operator import SelfHealingChaosOperator

app = FastAPI(
    title="SentinelMesh OS — AI Threat Hunter & Autonomous Self-Healing Plane",
    version="1.0.0"
)

classifier = MitreThreatClassifier()
healer = SelfHealingChaosOperator()

class TelemetryInspectRequest(BaseModel):
    source_ip: str
    target_service: str
    payload: str
    requests_per_sec: int = 10

class NodeHealthRequest(BaseModel):
    node_id: str
    service_name: str
    cpu_percent: float
    compromised_flag: bool = False

@app.get("/health")
def health_check():
    return {"status": "UP", "plane": "SentinelMesh-AI-Threat-Hunter-and-Chaos-Healer"}

@app.post("/api/v1/intelligence/classify")
def classify_telemetry(req: TelemetryInspectRequest):
    return classifier.evaluate_telemetry(
        req.source_ip, req.target_service, req.payload, req.requests_per_sec
    )

@app.post("/api/v1/intelligence/heal-node")
def trigger_self_healing(req: NodeHealthRequest):
    return healer.evaluate_and_heal_node(
        req.node_id, req.service_name, req.cpu_percent, req.compromised_flag
    )
