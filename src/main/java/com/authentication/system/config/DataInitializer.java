package com.authentication.system.config;

import com.authentication.system.entity.ERole;
import com.authentication.system.entity.Role;
import com.authentication.system.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {
    @Autowired
    RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        // Initialize roles
        try {
            if (roleRepository.count() == 0) {
                roleRepository.save(new Role(ERole.ROLE_USER));
                roleRepository.save(new Role(ERole.ROLE_MODERATOR));
                roleRepository.save(new Role(ERole.ROLE_ADMIN));
                System.out.println("Roles initialized successfully");
            }
        } catch (Exception e) {
            System.err.println("Error initializing roles: " + e.getMessage());
            e.printStackTrace();
        }
    }
}