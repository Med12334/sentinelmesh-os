package io.sentinelmesh.core.honeypot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@SpringBootApplication
@RestController
@RequestMapping("/api/v1/honeypot")
@CrossOrigin(origins = "*")
public class DeceptionHoneypotApplication {

    public record HoneypotTrapSession(
        UUID trapSessionId,
        String attackerIp,
        String decoyEndpoint,
        String capturedExploitPayload,
        String fakeResponseServed,
        Instant trappedAt
    ) {}

    private final List<HoneypotTrapSession> trappedSessions = new CopyOnWriteArrayList<>();

    public static void main(String[] args) {
        SpringApplication.run(DeceptionHoneypotApplication.class, args);
    }

    public record TrapRequest(String attackerIp, String decoyEndpoint, String exploitPayload) {}

    @PostMapping("/trap")
    public HoneypotTrapSession recordTrappedAttacker(@RequestBody TrapRequest req) {
        HoneypotTrapSession session = new HoneypotTrapSession(
            UUID.randomUUID(),
            req.attackerIp(),
            req.decoyEndpoint(),
            req.exploitPayload(),
            "200 OK [DECOY_SHADOW_DB: root:x:0:0:root:/root:/bin/bash]",
            Instant.now()
        );
        trappedSessions.add(0, session);
        return session;
    }

    @GetMapping("/sessions")
    public List<HoneypotTrapSession> listTrappedSessions() {
        return trappedSessions;
    }
}
