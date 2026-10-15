# SentinelMesh OS — 10-Layer Autonomous Cyber-Defense SOAR, Zero-Trust Mesh & Merkle Forensic Control Plane

SentinelMesh OS is a distributed Security Orchestration, Automation, and Response (SOAR) platform, active deception honeypot grid, and self-healing cloud security control plane. It combines 6 Java 17 Spring Boot microservices, 2 Python 3.11 AI Threat Hunting and Chaos Self-Healing engines, an Angular 18 SOC Command Center, a SHA-256 Merkle hash-chained PostgreSQL forensic ledger, and an IBM DB2 NIS2/ISO-27001 regulatory compliance vault.

## 10-Layer Architecture Overview

| Layer | Module | Technology Stack | Responsibility |
| :--- | :--- | :--- | :--- |
| **Layer 1** | `soc-command-center` | Angular 18, Signals, OnPush | Real-time SOC War Room UI, MITRE ATT&CK feed, and Merkle proof inspector. |
| **Layer 2** | `zero-trust-gateway` | Spring Cloud Gateway | Single ingress perimeter (`port 8000`) routing telemetry, SOAR, and honeypot traffic. |
| **Layer 3** | `telemetry-collector-service` | Java 17, Spring Boot 3.3, Kafka | High-throughput packet and syscall event ingestion into Apache Kafka. |
| **Layer 4** | `intelligence-plane/threat_hunter` | Python 3.11, FastAPI | Behavioral anomaly detector and MITRE ATT&CK tactic classifier (`T1190`, `T1059`, `T1498`, `T1110`). |
| **Layer 5** | `soar-orchestrator-service` | Java 17, Spring Boot 3.3 | Automated SOAR lockdown playbooks and Transactional Outbox publisher. |
| **Layer 6** | `deception-honeypot-service` | Java 17, Spring Boot 3.3 | Active cyber deception decoy environment that traps attackers and logs exploit payloads. |
| **Layer 7** | `intelligence-plane/chaos_healer` | Python 3.11, FastAPI | Autonomous self-healing operator that cordons compromised pods and spawns clean replicas. |
| **Layer 8** | `forensic_incident_ledger` | PostgreSQL 16 + SHA-256 Merkle Chain | Cryptographically hash-chained forensic evidence store (`previous_hash` + `merkle_hash`). |
| **Layer 9** | `compliance-db2-archiver` | IBM DB2 + Spring Data JPA | Immutable NIS2 & ISO-27001 regulatory incident archival (`COMPLIANCE_AUDIT_VAULT`). |
| **Layer 10** | `.github/workflows/ci.yml` | GitHub Actions | Parallel multi-language CI testing all 6 Java microservices (JUnit 5) and Python engines (Pytest). |

---

## Getting Started

### 1. Start PostgreSQL 16, IBM DB2 & Apache Kafka
    cd infra
    docker-compose up -d

### 2. Run the Python AI Threat Hunter & Chaos Self-Healing Plane
    cd intelligence-plane
    pip install -r requirements.txt
    uvicorn main:app --port 8085

### 3. Build & Test the 6-Module Java 17 Backend Mesh
    cd backend-mesh
    mvn clean test package

### 4. Launch the Angular 18 SOC Command Center
    cd soc-command-center
    npm install
    npm start
