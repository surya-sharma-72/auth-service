package com.app.auth.service;

import com.app.auth.config.JwtService;
import com.app.auth.dto.*;
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

import com.app.auth.entity.Otp;
import com.app.auth.repository.OtpRepository;

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

    private final OtpRepository otpRepository;
    private final EmailService emailService;


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


    public void sendVendorSignupOtp(VendorSignupRequest request) {

        if (!request.password().equals(request.confirmPassword())) {
            throw new RuntimeException("Passwords do not match");
        }

        if (userRepository.existsByEmail(request.email())) {
            throw new UserAlreadyExistsException("Email already registered");
        }

        String otp = String.valueOf((int)(Math.random() * 900000) + 100000);

        Otp otpEntity = Otp.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .otpCode(otp)
                .purpose("VENDOR_SIGNUP")
                .verified(false)
                .expiresAt(java.time.LocalDateTime.now().plusMinutes(5))
                .build();

        otpRepository.save(otpEntity);

        emailService.sendOtp(request.email(), otp);
    }






    public AuthResponse verifyVendorSignupOtp(VerifyOtpRequest request) {

        Otp otp = otpRepository
                .findTopByEmailAndPurposeOrderByCreatedAtDesc(
                        request.email(),
                        "VENDOR_SIGNUP"
                )
                .orElseThrow(() ->
                        new RuntimeException("OTP not found"));

        if (otp.getExpiresAt().isBefore(java.time.LocalDateTime.now())) {
            throw new RuntimeException("OTP expired");
        }

        if (!otp.getOtpCode().equals(request.otp())) {
            throw new RuntimeException("Invalid OTP");
        }

        Role vendorRole = roleRepository.findByName("VENDOR")
                .orElseThrow(() ->
                        new RuntimeException("Vendor role not found"));

        User user = User.builder()
                .email(otp.getEmail())
                .password(otp.getPassword())
                .role(vendorRole)
                .enabled(false) // important
                .build();

        userRepository.save(user);

        String token = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(token)
                .build();
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