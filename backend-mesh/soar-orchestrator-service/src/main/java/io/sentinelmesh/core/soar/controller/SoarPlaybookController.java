package io.sentinelmesh.core.soar.controller;

import io.sentinelmesh.core.events.SecurityIncidentEvent;
import io.sentinelmesh.core.soar.entity.ForensicIncidentRecord;
import io.sentinelmesh.core.soar.repository.ForensicIncidentRepository;
import io.sentinelmesh.core.soar.service.SoarPlaybookService;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/api/v1/soar")
@CrossOrigin(origins = "*")
public class SoarPlaybookController {

    private final SoarPlaybookService soarService;
    private final ForensicIncidentRepository incidentRepository;

    public SoarPlaybookController(SoarPlaybookService soarService,
                                  ForensicIncidentRepository incidentRepository) {
        this.soarService = soarService;
        this.incidentRepository = incidentRepository;
    }

    public record TriggerSoarRequest(String sourceIp, String targetService, String mitreTacticId, BigDecimal threatScore) {}

    @PostMapping("/execute")
    public SecurityIncidentEvent triggerPlaybook(@RequestBody TriggerSoarRequest req) throws Exception {
        return soarService.executePlaybookAndSealForensics(
            req.sourceIp(), req.targetService(), req.mitreTacticId(), req.threatScore()
        );
    }

    @GetMapping("/forensic-ledger")
    public List<ForensicIncidentRecord> getForensicChain() {
        return incidentRepository.findAll();
    }
}
