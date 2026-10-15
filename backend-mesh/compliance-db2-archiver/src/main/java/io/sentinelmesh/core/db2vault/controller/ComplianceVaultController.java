package io.sentinelmesh.core.db2vault.controller;

import io.sentinelmesh.core.db2vault.entity.ComplianceAuditEntry;
import io.sentinelmesh.core.db2vault.repository.ComplianceAuditRepository;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/compliance-vault")
@CrossOrigin(origins = "*")
public class ComplianceVaultController {

    private final ComplianceAuditRepository repository;

    public ComplianceVaultController(ComplianceAuditRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public List<ComplianceAuditEntry> listArchivedAudits() {
        return repository.findAll();
    }
}
