package com.example.jwtrbac.config;

import com.example.jwtrbac.model.Role;
import com.example.jwtrbac.model.RoleType;
import com.example.jwtrbac.model.User;
import com.example.jwtrbac.repository.RoleRepository;
import com.example.jwtrbac.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.seed-initial-data:true}")
    private boolean seedInitialData;

    @Value("${app.admin.default-username:admin}")
    private String adminUsername;

    @Value("${app.admin.default-email:admin@example.com}")
    private String adminEmail;

    @Value("${app.admin.default-password:Admin@12345}")
    private String adminPassword;

    public DataInitializer(RoleRepository roleRepository,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(String... args) {
        if (!seedInitialData) {
            return;
        }

        // Initialize Roles if they do not exist
        Role roleUser = roleRepository.findByName(RoleType.ROLE_USER)
                .orElseGet(() -> roleRepository.save(new Role(RoleType.ROLE_USER)));

        Role roleAdmin = roleRepository.findByName(RoleType.ROLE_ADMIN)
                .orElseGet(() -> roleRepository.save(new Role(RoleType.ROLE_ADMIN)));

        // Seed Default Admin User if not present
        if (!userRepository.existsByUsername(adminUsername)) {
            User admin = new User(
                    adminUsername,
                    adminEmail,
                    passwordEncoder.encode(adminPassword)
            );
            Set<Role> adminRoles = new HashSet<>();
            adminRoles.add(roleUser);
            adminRoles.add(roleAdmin);
            admin.setRoles(adminRoles);
            userRepository.save(admin);
            logger.info("Default administrator created with username: {}", adminUsername);
        }

        // Seed Default Regular User if not present
        String defaultUsername = "testuser";
        if (!userRepository.existsByUsername(defaultUsername)) {
            User regularUser = new User(
                    defaultUsername,
                    "testuser@example.com",
                    passwordEncoder.encode("User@12345")
            );
            Set<Role> userRoles = new HashSet<>();
            userRoles.add(roleUser);
            regularUser.setRoles(userRoles);
            userRepository.save(regularUser);
            logger.info("Default standard user created with username: {}", defaultUsername);
        }
    }
}
