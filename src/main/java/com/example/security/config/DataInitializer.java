package com.example.security.config;

import com.example.security.model.Role;
import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Data Initializer.
 *
 * Creates default admin user on application startup for testing.
 */
@Configuration
public class DataInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    public CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Create admin user if not exists
            if (!userRepository.existsByEmail("admin@example.com")) {
                User admin = new User();
                admin.setName("Admin User");
                admin.setEmail("admin@example.com");
                admin.setPassword(passwordEncoder.encode("Admin123!"));
                admin.setRole(Role.ADMIN);
                userRepository.save(admin);
                logger.info("Created default admin user: admin@example.com / Admin123!");
            }

            // Create regular user if not exists
            if (!userRepository.existsByEmail("user@example.com")) {
                User user = new User();
                user.setName("Regular User");
                user.setEmail("user@example.com");
                user.setPassword(passwordEncoder.encode("User1234"));
                user.setRole(Role.USER);
                userRepository.save(user);
                logger.info("Created default user: user@example.com / User1234");
            }
        };
    }
}
