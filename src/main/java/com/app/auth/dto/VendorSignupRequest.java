package com.app.auth.dto;

public record VendorSignupRequest(
        String email,
        String password,
        String confirmPassword
) {
}