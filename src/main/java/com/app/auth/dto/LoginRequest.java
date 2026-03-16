package com.app.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {

    @NotBlank(message = "Email or phone number is required")
    private String identifier;

    @NotBlank(message = "Password is required")
    private String password;
}