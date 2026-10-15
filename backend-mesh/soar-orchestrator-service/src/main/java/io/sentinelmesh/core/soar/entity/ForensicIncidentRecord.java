package io.sentinelmesh.core.soar.entity;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "forensic_incident_ledger")
public class ForensicIncidentRecord {

    @Id
    @Column(name = "incident_id")
    private UUID incidentId;

    @Column(name = "source_ip", length = 64, nullable = false)
    private String sourceIp;

    @Column(name = "target_service", length = 64, nullable = false)
    private String targetService;

    @Column(name = "mitre_tactic_id", length = 32, nullable = false)
    private String mitreTacticId;

    @Column(name = "threat_score", precision = 4, scale = 2, nullable = false)
    private BigDecimal threatScore;

    @Column(name = "remediation_action", length = 64, nullable = false)
    private String remediationAction;

    @Column(name = "previous_hash", length = 64, nullable = false)
    private String previousHash;

    @Column(name = "merkle_hash", length = 64, nullable = false, unique = true)
    private String merkleHash;

    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public ForensicIncidentRecord() {}

    public ForensicIncidentRecord(UUID incidentId, String sourceIp, String targetService,
                                  String mitreTacticId, BigDecimal threatScore,
                                  String remediationAction, String previousHash, String merkleHash) {
        this.incidentId = incidentId;
        this.sourceIp = sourceIp;
        this.targetService = targetService;
        this.mitreTacticId = mitreTacticId;
        this.threatScore = threatScore;
        this.remediationAction = remediationAction;
        this.previousHash = previousHash;
        this.merkleHash = merkleHash;
        this.createdAt = Instant.now();
    }

    public UUID getIncidentId() { return incidentId; }
    public String getSourceIp() { return sourceIp; }
    public String getTargetService() { return targetService; }
    public String getMitreTacticId() { return mitreTacticId; }
    public BigDecimal getThreatScore() { return threatScore; }
    public String getRemediationAction() { return remediationAction; }
    public String getPreviousHash() { return previousHash; }
    public String getMerkleHash() { return merkleHash; }
}
