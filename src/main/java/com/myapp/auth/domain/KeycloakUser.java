package com.myapp.auth.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;


@Data
public class KeycloakUser {
    private String username;
    private String email;

    @JsonProperty("firstName")
    private String firstName;

    @JsonProperty("lastName")
    private String lastName;

    private boolean enabled;
    private List<Credential> credentials;
}