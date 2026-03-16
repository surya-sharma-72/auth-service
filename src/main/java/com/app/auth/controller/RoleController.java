package com.app.auth.controller;

import com.app.auth.dto.CreateRoleRequest;
import com.app.auth.service.RoleService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @PostMapping
    public ResponseEntity<String> createRole(
            @Valid @RequestBody CreateRoleRequest request) {

        roleService.createRole(request);

        return ResponseEntity.ok("Role created successfully");
    }
}
