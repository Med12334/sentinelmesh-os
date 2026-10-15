package io.sentinelmesh.core.db2vault.kafka;

import io.sentinelmesh.core.db2vault.entity.ComplianceAuditEntry;
import io.sentinelmesh.core.db2vault.repository.ComplianceAuditRepository;
import io.sentinelmesh.core.events.SecurityIncidentEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Db2ComplianceArchiveConsumerTest {

    @Mock
    private ComplianceAuditRepository repository;

    @InjectMocks
    private Db2ComplianceArchiveConsumer consumer;

    @Test
    void shouldSkipDuplicateIncidentArchiveInDb2Vault() {
        UUID incidentId = UUID.randomUUID();
        SecurityIncidentEvent event = new SecurityIncidentEvent(
            incidentId, "185.220.101.44", "auth-api", "T1110_CREDENTIAL_BRUTE_FORCE",
            new BigDecimal("8.50"), "BLACKLIST_IP", "hash123", "NIS2_ISO27001", Instant.now()
        );

        when(repository.findByIncidentRefUuid(incidentId.toString()))
            .thenReturn(Optional.of(new ComplianceAuditEntry()));

        consumer.archiveIncidentToDb2(event);

        verify(repository, never()).save(any());
    }
}
