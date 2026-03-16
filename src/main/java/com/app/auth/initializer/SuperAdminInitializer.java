package com.app.auth.initializer;

import com.app.auth.entity.Role;
import com.app.auth.entity.User;
import com.app.auth.repository.RoleRepository;
import com.app.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class SuperAdminInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${superadmin.email}")
    private String superAdminEmail;

    @Value("${superadmin.password}")
    private String superAdminPassword;

    @Override
    public void run(ApplicationArguments args) {

        // 1️⃣ Ensure SUPER_ADMIN role exists
        Role superAdminRole = roleRepository.findByName("SUPER_ADMIN")
                .orElseGet(() -> roleRepository.save(
                        Role.builder()
                                .name("SUPER_ADMIN")
                                .description("System Super Administrator")
                                .build()
                ));

        // 2️⃣ Ensure CUSTOMER role exists
        roleRepository.findByName("CUSTOMER")
                .orElseGet(() -> roleRepository.save(
                        Role.builder()
                                .name("CUSTOMER")
                                .description("Customer Role")
                                .build()
                ));

        // 3️⃣ Check if SUPER_ADMIN user exists
        boolean exists = userRepository.existsByEmail(superAdminEmail);

        if (exists) {
            return;
        }

        // 4️⃣ Create SUPER_ADMIN user
        User superAdmin = User.builder()
                .email(superAdminEmail)
                .password(passwordEncoder.encode(superAdminPassword))
                .role(superAdminRole)
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .build();

        userRepository.save(superAdmin);

        System.out.println("SUPER_ADMIN created successfully");
    }
}