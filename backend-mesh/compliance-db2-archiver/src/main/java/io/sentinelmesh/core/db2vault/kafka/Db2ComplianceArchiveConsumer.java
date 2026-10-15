package io.sentinelmesh.core.db2vault.kafka;

import io.sentinelmesh.core.db2vault.entity.ComplianceAuditEntry;
import io.sentinelmesh.core.db2vault.repository.ComplianceAuditRepository;
import io.sentinelmesh.core.events.SecurityIncidentEvent;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class Db2ComplianceArchiveConsumer {

    private final ComplianceAuditRepository repository;

    public Db2ComplianceArchiveConsumer(ComplianceAuditRepository repository) {
        this.repository = repository;
    }

    @KafkaListener(topics = "compliance-db2-archive", groupId = "db2-compliance-vault-group")
    @Transactional
    public void archiveIncidentToDb2(SecurityIncidentEvent event) {
        String refUuid = event.incidentId().toString();
        if (repository.findByIncidentRefUuid(refUuid).isPresent()) {
            return;
        }

        ComplianceAuditEntry entry = new ComplianceAuditEntry(
            refUuid,
            event.sourceIp(),
            event.mitreTacticId(),
            event.threatScore(),
            event.soarActionTaken(),
            event.merkleProofHash(),
            event.regulatoryFramework()
        );
        repository.save(entry);
    }
}
