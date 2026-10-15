package io.sentinelmesh.core.soar.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.sentinelmesh.core.events.SecurityIncidentEvent;
import io.sentinelmesh.core.soar.entity.ForensicIncidentRecord;
import io.sentinelmesh.core.soar.entity.OutboxEvent;
import io.sentinelmesh.core.soar.repository.ForensicIncidentRepository;
import io.sentinelmesh.core.soar.repository.OutboxEventRepository;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
public class SoarPlaybookService {

    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    private final ForensicIncidentRepository incidentRepository;
    private final OutboxEventRepository outboxRepository;
    private final KafkaTemplate<String, SecurityIncidentEvent> kafkaTemplate;
    private final ObjectMapper objectMapper;

    public SoarPlaybookService(ForensicIncidentRepository incidentRepository,
                               OutboxEventRepository outboxRepository,
                               KafkaTemplate<String, SecurityIncidentEvent> kafkaTemplate,
                               ObjectMapper objectMapper) {
        this.incidentRepository = incidentRepository;
        this.outboxRepository = outboxRepository;
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public SecurityIncidentEvent executePlaybookAndSealForensics(
            String sourceIp, String targetService, String mitreTacticId, BigDecimal threatScore) throws Exception {

        String prevHash = incidentRepository.findTopByOrderByCreatedAtDesc()
                .map(ForensicIncidentRecord::getMerkleHash)
                .orElse(GENESIS_HASH);

        String action = threatScore.compareTo(new BigDecimal("9.00")) >= 0
                ? "ISOLATE_POD_AND_REROUTE_HONEYPOT"
                : "BLACKLIST_IP_AT_ZERO_TRUST_GATEWAY";

        UUID incidentId = UUID.randomUUID();
        String merkleHash = computeSha256MerkleHash(prevHash, incidentId, sourceIp, mitreTacticId, action);

        ForensicIncidentRecord record = new ForensicIncidentRecord(
            incidentId, sourceIp, targetService, mitreTacticId, threatScore, action, prevHash, merkleHash
        );
        incidentRepository.save(record);

        SecurityIncidentEvent event = new SecurityIncidentEvent(
            incidentId, sourceIp, targetService, mitreTacticId,
            threatScore, action, merkleHash, "NIS2_ISO27001", Instant.now()
        );

        OutboxEvent outbox = new OutboxEvent(
            "SECURITY_INCIDENT",
            incidentId.toString(),
            "compliance-db2-archive",
            objectMapper.writeValueAsString(event)
        );
        outboxRepository.save(outbox);
        return event;
    }

    @Scheduled(fixedDelay = 2000)
    @Transactional
    public void relayOutboxEventsToKafka() throws Exception {
        List<OutboxEvent> pending = outboxRepository.findTop50ByProcessedFalseOrderByCreatedAtAsc();
        for (OutboxEvent item : pending) {
            SecurityIncidentEvent ev = objectMapper.readValue(item.getPayload(), SecurityIncidentEvent.class);
            kafkaTemplate.send(item.getEventType(), item.getAggregateId(), ev);
            item.markProcessed();
            outboxRepository.save(item);
        }
    }

    public String computeSha256MerkleHash(String prevHash, UUID id, String ip, String tactic, String action) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String raw = prevHash + "|" + id + "|" + ip + "|" + tactic + "|" + action;
        byte[] hashBytes = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hashBytes);
    }
}
