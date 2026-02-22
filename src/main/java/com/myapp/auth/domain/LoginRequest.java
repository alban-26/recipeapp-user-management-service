package com.myapp.auth.domain;

import lombok.Value;

@Value
public class LoginRequest {
    String username;
    String password;
}
