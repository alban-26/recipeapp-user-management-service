package com.myapp.auth.domain;

import lombok.Value;

@Value
public class LogoutRequest {
    String refreshToken;
}
