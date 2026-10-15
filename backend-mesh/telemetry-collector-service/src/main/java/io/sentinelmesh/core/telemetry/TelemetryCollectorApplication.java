package io.sentinelmesh.core.telemetry;

import io.sentinelmesh.core.events.SecurityIncidentEvent;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@SpringBootApplication
@RestController
@RequestMapping("/api/v1/telemetry")
@CrossOrigin(origins = "*")
public class TelemetryCollectorApplication {

    private final KafkaTemplate<String, SecurityIncidentEvent> kafkaTemplate;

    public TelemetryCollectorApplication(KafkaTemplate<String, SecurityIncidentEvent> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public static void main(String[] args) {
        SpringApplication.run(TelemetryCollectorApplication.class, args);
    }

    public record RawPacketFlow(String sourceIp, String targetService, String mitreTacticId, BigDecimal threatScore) {}

    @PostMapping("/ingest")
    public Map<String, Object> ingestTelemetryEvent(@RequestBody RawPacketFlow flow) {
        SecurityIncidentEvent event = new SecurityIncidentEvent(
            UUID.randomUUID(),
            flow.sourceIp(),
            flow.targetService(),
            flow.mitreTacticId(),
            flow.threatScore(),
            "TELEMETRY_CAPTURED",
            "PENDING_MERKLE_SEAL",
            "NIS2_ISO27001",
            Instant.now()
        );
        kafkaTemplate.send("raw-security-telemetry", flow.sourceIp(), event);
        return Map.of("status", "INGESTED", "incidentId", event.incidentId());
    }
}
