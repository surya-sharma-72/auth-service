package com.app.auth.service;

import com.app.auth.config.JwtService;
import com.app.auth.dto.AuthResponse;
import com.app.auth.dto.LoginRequest;
import com.app.auth.dto.OtpLoginRequest;
import com.app.auth.dto.RegisterRequest;
import com.app.auth.entity.Role;
import com.app.auth.entity.User;
import com.app.auth.exception.UserAlreadyExistsException;
import com.app.auth.exception.UserNotFoundException;
import com.app.auth.repository.RoleRepository;
import com.app.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${dev.otp.enabled:false}")
    private boolean devOtpEnabled;

    @Value("${dev.otp.phone}")
    private String devPhone;

    @Value("${dev.otp.code}")
    private String devOtp;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;


    // LOGIN WITH EMAIL OR PHONE + PASSWORD
    public AuthResponse login(LoginRequest request) {

        String identifier = request.getIdentifier();

        User user = userRepository
                .findByEmailOrPhoneNumber(identifier, identifier)
                .orElseThrow(() ->
                        new UserNotFoundException("User not found"));

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        identifier,
                        request.getPassword()
                )
        );

        String token = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(token)
                .build();
    }


    // CUSTOMER REGISTRATION
    public void registerCustomer(RegisterRequest request) {

        if ((request.getEmail() == null || request.getEmail().isBlank()) &&
                (request.getPhoneNumber() == null || request.getPhoneNumber().isBlank())) {

            throw new RuntimeException("Email or phone number is required");
        }

        if (request.getEmail() != null &&
                userRepository.existsByEmail(request.getEmail())) {

            throw new UserAlreadyExistsException("Email already registered");
        }

        if (request.getPhoneNumber() != null &&
                userRepository.existsByPhoneNumber(request.getPhoneNumber())) {

            throw new UserAlreadyExistsException("Phone number already registered");
        }

        Role customerRole = roleRepository.findByName("CUSTOMER")
                .orElseThrow(() ->
                        new RuntimeException("Customer role not found"));

        User user = User.builder()
                .email(request.getEmail())
                .phoneNumber(request.getPhoneNumber())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(customerRole)
                .enabled(true)
                .build();

        userRepository.save(user);
    }


    // OTP LOGIN (DEV MODE)
    public AuthResponse loginWithOtp(OtpLoginRequest request) {

        if (devOtpEnabled &&
                request.getPhoneNumber().equals(devPhone) &&
                request.getOtp().equals(devOtp)) {

            User user = userRepository.findByPhoneNumber(request.getPhoneNumber())
                    .orElseThrow(() ->
                            new UserNotFoundException("User not found"));

            String token = jwtService.generateToken(user);

            return AuthResponse.builder()
                    .token(token)
                    .build();
        }

        throw new RuntimeException("Invalid OTP");
    }
}