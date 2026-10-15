export interface ForensicIncidentRecord {
  incidentId: string;
  sourceIp: string;
  targetService: string;
  mitreTacticId: string;
  threatScore: number;
  remediationAction: string;
  previousHash: string;
  merkleHash: string;
}

export interface HoneypotTrapSession {
  trapSessionId: string;
  attackerIp: string;
  decoyEndpoint: string;
  capturedExploitPayload: string;
  fakeResponseServed: string;
  trappedAt: string;
}

export interface ComplianceAuditEntry {
  auditSeqId: number;
  incidentRefUuid: string;
  attackerIp: string;
  mitreTacticCode: string;
  severityScore: number;
  soarActionTaken: string;
  merkleProofHash: string;
  regulatoryFramework: string;
  archivedAt: string;
}
