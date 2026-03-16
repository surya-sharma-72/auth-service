package com.app.auth.service;

import com.app.auth.entity.User;
import com.app.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String identifier)
            throws UsernameNotFoundException {

        User user = userRepository
                .findByEmailOrPhoneNumber(identifier, identifier)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found"));

        // ensure username is never null
        String principal = user.getEmail() != null
                ? user.getEmail()
                : user.getPhoneNumber();

        return org.springframework.security.core.userdetails.User
                .withUsername(principal)
                .password(user.getPassword())
                .authorities("ROLE_" + user.getRole().getName())
                .disabled(!user.getEnabled())
                .build();
    }
}