package io.sentinelmesh.core.db2vault.repository;

import io.sentinelmesh.core.db2vault.entity.ComplianceAuditEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ComplianceAuditRepository extends JpaRepository<ComplianceAuditEntry, Long> {
    Optional<ComplianceAuditEntry> findByIncidentRefUuid(String incidentRefUuid);
}
