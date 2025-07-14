package com.chatterbox.user_service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
public class TokenServiceTest {

    @Container
    static GenericContainer<?> redisContainer = new GenericContainer<>("redis:6.0.2")
            .withExposedPorts(6379);

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Container
    static MySQLContainer<?> mySQLContainer = new MySQLContainer<>("mysql:8.0")
            .withUsername("testuser")
            .withPassword("testpass")
            .withDatabaseName("testdb");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", mySQLContainer::getJdbcUrl);
        registry.add("spring.datasource.username", mySQLContainer::getUsername);
        registry.add("spring.datasource.password", mySQLContainer::getPassword);

        registry.add("spring.data.redis.host", redisContainer::getHost);
        registry.add("spring.data.redis.port", redisContainer::getFirstMappedPort);
    }

    @DisplayName("MySQL JDBC Url 확인")
    @Test
    void MySQLJDBCUrlTest() {
        System.out.println(mySQLContainer.getJdbcUrl());
    }

    @DisplayName("Redis 접속 확인")
    @Test
    void RedisTest() {
        System.out.println("Redis Host: " + redisContainer.getHost());
        System.out.println("Redis Port: " + redisContainer.getFirstMappedPort());
        System.out.println("RedisTemplate: " + redisTemplate);

        // Redis 연결 테스트
        redisTemplate.opsForValue().set("test-key", "test-value");
        String value = redisTemplate.opsForValue().get("test-key");
        System.out.println("Retrieved value: " + value);
    }
}