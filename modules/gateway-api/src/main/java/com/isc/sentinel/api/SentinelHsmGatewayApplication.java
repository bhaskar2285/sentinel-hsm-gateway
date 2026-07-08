package com.isc.sentinel.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(scanBasePackages = "com.isc.sentinel")
@EntityScan(basePackages = "com.isc.sentinel.persistence.entity")
@EnableJpaRepositories(basePackages = "com.isc.sentinel.persistence.repo")
@EnableScheduling
public class SentinelHsmGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(SentinelHsmGatewayApplication.class, args);
    }
}
