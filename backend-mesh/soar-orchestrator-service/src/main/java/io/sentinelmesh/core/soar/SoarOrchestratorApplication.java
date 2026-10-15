package io.sentinelmesh.core.soar;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SoarOrchestratorApplication {
    public static void main(String[] args) {
        SpringApplication.run(SoarOrchestratorApplication.class, args);
    }
}
