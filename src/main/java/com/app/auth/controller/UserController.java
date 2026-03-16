package com.app.auth.controller;

import com.app.auth.dto.CreateUserRequest;
import com.app.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<String> createUser(
            @Valid @RequestBody CreateUserRequest request) {

        userService.createUser(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body("User created successfully");
    }
}