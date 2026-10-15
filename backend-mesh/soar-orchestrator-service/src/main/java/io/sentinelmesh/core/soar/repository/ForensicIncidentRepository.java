package io.sentinelmesh.core.soar.repository;

import io.sentinelmesh.core.soar.entity.ForensicIncidentRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface ForensicIncidentRepository extends JpaRepository<ForensicIncidentRecord, UUID> {
    Optional<ForensicIncidentRecord> findTopByOrderByCreatedAtDesc();
}
