package com.myapp.auth.domain;

import lombok.Value;

@Value
public class RegisterRequest {
    String email;
    String password;
}
