package io.sentinelmesh.core.events;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

public record SecurityIncidentEvent(
    UUID incidentId,
    String sourceIp,
    String targetService,
    String mitreTacticId,
    BigDecimal threatScore,
    String soarActionTaken,
    String merkleProofHash,
    String regulatoryFramework,
    Instant occurredAt
) {}
