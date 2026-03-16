package com.app.auth.dto;

public record VerifyOtpRequest(
        String email,
        String otp
) {
}