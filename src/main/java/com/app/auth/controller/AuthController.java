package com.app.auth.controller;

import com.app.auth.dto.AuthResponse;
import com.app.auth.dto.LoginRequest;
import com.app.auth.dto.OtpLoginRequest;
import com.app.auth.dto.RegisterRequest;
import com.app.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import com.app.auth.dto.UserIdResponse;

import com.app.auth.dto.VendorSignupRequest;
import com.app.auth.dto.VerifyOtpRequest;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request) {

        AuthResponse response = authService.login(request);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest request) {

        authService.registerCustomer(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body("Account created successfully");
    }

    @PostMapping("/login/otp")
    public ResponseEntity<AuthResponse> loginWithOtp(
            @RequestBody OtpLoginRequest request) {

        return ResponseEntity.ok(authService.loginWithOtp(request));
    }



    @GetMapping("/user-id")
    public ResponseEntity<UserIdResponse> getUserId(Authentication authentication) {

        Long userId = (Long) authentication.getPrincipal();

        return ResponseEntity.ok(new UserIdResponse(userId));
    }



    @PostMapping("/vendor/signup/request-otp")
    public ResponseEntity<String> requestVendorSignupOtp(
            @RequestBody VendorSignupRequest request) {

        authService.sendVendorSignupOtp(request);

        return ResponseEntity.ok("OTP sent to email");
    }



    @PostMapping("/vendor/signup/verify-otp")
    public ResponseEntity<AuthResponse> verifyVendorSignupOtp(
            @RequestBody VerifyOtpRequest request) {

        return ResponseEntity.ok(
                authService.verifyVendorSignupOtp(request)
        );
    }









}