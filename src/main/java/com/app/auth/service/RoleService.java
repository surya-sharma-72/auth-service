package com.app.auth.service;

import com.app.auth.dto.CreateRoleRequest;
import com.app.auth.entity.Role;
import com.app.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;

    public void createRole(CreateRoleRequest request) {

        if (roleRepository.findByName(request.getName()).isPresent()) {
            throw new RuntimeException("Role already exists");
        }

        Role role = Role.builder()
                .name(request.getName())
                .description(request.getDescription())
                .build();

        roleRepository.save(role);
    }
}