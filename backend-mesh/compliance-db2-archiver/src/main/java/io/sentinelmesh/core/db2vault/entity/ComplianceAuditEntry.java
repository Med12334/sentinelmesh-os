package io.sentinelmesh.core.db2vault.entity;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;

@Entity
@Table(name = "COMPLIANCE_AUDIT_VAULT")
public class ComplianceAuditEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "AUDIT_SEQ_ID")
    private Long auditSeqId;

    @Column(name = "INCIDENT_REF_UUID", length = 36, nullable = false, unique = true)
    private String incidentRefUuid;

    @Column(name = "ATTACKER_IP", length = 64, nullable = false)
    private String attackerIp;

    @Column(name = "MITRE_TACTIC_CODE", length = 32, nullable = false)
    private String mitreTacticCode;

    @Column(name = "SEVERITY_SCORE", precision = 4, scale = 2, nullable = false)
    private BigDecimal severityScore;

    @Column(name = "SOAR_ACTION_TAKEN", length = 64, nullable = false)
    private String soarActionTaken;

    @Column(name = "MERKLE_PROOF_HASH", length = 64, nullable = false)
    private String merkleProofHash;

    @Column(name = "REGULATORY_FRAMEWORK", length = 32, nullable = false)
    private String regulatoryFramework;

    @Column(name = "ARCHIVED_AT", nullable = false)
    private Instant archivedAt = Instant.now();

    public ComplianceAuditEntry() {}

    public ComplianceAuditEntry(String incidentRefUuid, String attackerIp, String mitreTacticCode,
                                BigDecimal severityScore, String soarActionTaken,
                                String merkleProofHash, String regulatoryFramework) {
        this.incidentRefUuid = incidentRefUuid;
        this.attackerIp = attackerIp;
        this.mitreTacticCode = mitreTacticCode;
        this.severityScore = severityScore;
        this.soarActionTaken = soarActionTaken;
        this.merkleProofHash = merkleProofHash;
        this.regulatoryFramework = regulatoryFramework;
        this.archivedAt = Instant.now();
    }

    public Long getAuditSeqId() { return auditSeqId; }
    public String getIncidentRefUuid() { return incidentRefUuid; }
    public String getAttackerIp() { return attackerIp; }
    public String getMitreTacticCode() { return mitreTacticCode; }
    public BigDecimal getSeverityScore() { return severityScore; }
    public String getSoarActionTaken() { return soarActionTaken; }
    public String getMerkleProofHash() { return merkleProofHash; }
    public String getRegulatoryFramework() { return regulatoryFramework; }
    public Instant getArchivedAt() { return archivedAt; }
}
