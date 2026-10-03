package com.vc.config;

import com.vc.user.User;
import com.vc.user.UserRole;
import com.vc.auth.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Spring Boot automatically injects your database repository and BCrypt bean
    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // Only run data seeding if your users table grid is completely empty
        if (userRepository.count() == 0) {
            
            // 1. Seed the ADMIN profile record
            userRepository.save(User.builder()
                    .username("Admin User")
                    .email("admin@example.com")
                    .password(passwordEncoder.encode("admin123")) // Securely hashes raw plain text
                    .role(UserRole.ADMIN)
                    .isActive(true)
                    .build());

            // 2. Seed the STAFF profile record
            userRepository.save(User.builder()
                    .username("Staff User")
                    .email("staff@example.com")
                    .password(passwordEncoder.encode("staff123"))
                    .role(UserRole.STAFF)
                    .isActive(true)
                    .build());

            // 3. Seed the STUDENT profile record
            userRepository.save(User.builder()
                    .username("Student User")
                    .email("student@example.com")
                    .password(passwordEncoder.encode("student123"))
                    .role(UserRole.STUDENT)
                    .isActive(true)
                    .build());

            System.out.println("====== VEDANTA PORTAL DATA SEEDING COMPLETE ======");
            System.out.println("Accounts ready: admin@example.com, staff@example.com, student@example.com");
        }
    }
}
