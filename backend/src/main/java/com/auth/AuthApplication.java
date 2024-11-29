package com.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
// import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
@SpringBootApplication
// @EnableMongoRepositories(basePackages = "com.auth.repository")  // Ensure MongoDB repositories are scanned
@EnableScheduling
public class AuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}
