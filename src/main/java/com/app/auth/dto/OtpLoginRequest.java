package com.app.auth.dto;

import lombok.Data;

@Data
public class OtpLoginRequest {

    private String phoneNumber;
    private String otp;

}