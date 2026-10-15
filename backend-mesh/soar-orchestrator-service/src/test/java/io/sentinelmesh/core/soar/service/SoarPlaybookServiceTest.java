package io.sentinelmesh.core.soar.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.sentinelmesh.core.events.SecurityIncidentEvent;
import io.sentinelmesh.core.soar.entity.ForensicIncidentRecord;
import io.sentinelmesh.core.soar.entity.OutboxEvent;
import io.sentinelmesh.core.soar.repository.ForensicIncidentRepository;
import io.sentinelmesh.core.soar.repository.OutboxEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;

import java.math.BigDecimal;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SoarPlaybookServiceTest {

    @Mock
    private ForensicIncidentRepository incidentRepository;

    @Mock
    private OutboxEventRepository outboxRepository;

    @Mock
    private KafkaTemplate<String, SecurityIncidentEvent> kafkaTemplate;

    private SoarPlaybookService soarService;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        soarService = new SoarPlaybookService(incidentRepository, outboxRepository, kafkaTemplate, mapper);
    }

    @Test
    void shouldSealIncidentWithSha256MerkleHashAndSaveOutboxEvent() throws Exception {
        when(incidentRepository.findTopByOrderByCreatedAtDesc()).thenReturn(Optional.empty());

        SecurityIncidentEvent event = soarService.executePlaybookAndSealForensics(
            "185.220.101.44", "payment-gateway", "T1190_EXPLOIT_PUBLIC_APP", new BigDecimal("9.50")
        );

        assertEquals("ISOLATE_POD_AND_REROUTE_HONEYPOT", event.soarActionTaken());
        assertNotNull(event.merkleProofHash());
        assertEquals(64, event.merkleProofHash().length());

        ArgumentCaptor<ForensicIncidentRecord> recordCaptor = ArgumentCaptor.forClass(ForensicIncidentRecord.class);
        verify(incidentRepository, times(1)).save(recordCaptor.capture());
        assertEquals(event.merkleProofHash(), recordCaptor.getValue().getMerkleHash());

        ArgumentCaptor<OutboxEvent> outboxCaptor = ArgumentCaptor.forClass(OutboxEvent.class);
        verify(outboxRepository, times(1)).save(outboxCaptor.capture());
        assertEquals("compliance-db2-archive", outboxCaptor.getValue().getEventType());
    }
}
