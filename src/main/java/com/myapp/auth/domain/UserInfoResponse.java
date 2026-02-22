package com.myapp.auth.domain;

public record UserInfoResponse(
        String id,
        String username,
        String firstName,
        String lastName
) {}
