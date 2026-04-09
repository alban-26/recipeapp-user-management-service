package com.myapp.auth.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.myapp.auth.domain.Credential;
import com.myapp.auth.domain.KeycloakUser;
import com.myapp.auth.domain.RegisterRequest;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.codec.BodyCodec;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.List;
import org.eclipse.microprofile.config.inject.ConfigProperty;
@ApplicationScoped
public class KeycloakService {

    private static final Logger LOGGER = Logger.getLogger(KeycloakService.class);


    @ConfigProperty(name = "keycloak.url")
    String KEYCLOAK_URL;

    @ConfigProperty(name = "keycloak.realm")
    String REALM;

    @ConfigProperty(name = "keycloak.client-id")
    String CLIENT_ID;

    @ConfigProperty(name = "keycloak.client-secret")
    String CLIENT_SECRET;

    @ConfigProperty(name = "keycloak.admin.client-id")
    String ADMIN_CLIENT_ID;

    @ConfigProperty(name = "keycloak.admin.client-secret")
    String ADMIN_CLIENT_SECRET;

    @Inject
    WebClient webClient;

    @Inject
    ObjectMapper objectMapper;

    public Future<Void> registerUser(RegisterRequest request) {
        KeycloakUser user = createUserObject(request);
        return createUser(user)
                .compose(this::sendVerificationEmail)
                .onSuccess(v -> LOGGER.info("User registration successful, verification email sent"))
                .onFailure(e -> LOGGER.error("User registration failed", e))
                .mapEmpty();
    }

    public Future<JsonObject> login(String username, String password) {
        String url = KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/token";
        String formData = "client_id=" + CLIENT_ID +
                "&client_secret=" + CLIENT_SECRET +
                "&username=" + username +
                "&password=" + password +
                "&grant_type=password";

        Promise<JsonObject> promise = Promise.promise();

        webClient.postAbs(url)
                .putHeader("Content-Type", "application/x-www-form-urlencoded")
                .sendBuffer(Buffer.buffer(formData), ar -> {
                    if (ar.succeeded()) {
                        HttpResponse<Buffer> response = ar.result();
                        if (response.statusCode() == 200) {
                            JsonObject tokenResponse = response.bodyAsJsonObject();
                            promise.complete(tokenResponse);
                        } else {
                            LOGGER.errorf("Login failed: %d - %s", response.statusCode(), response.bodyAsString());
                            promise.fail("Login failed: " + response.statusCode());
                        }
                    } else {
                        LOGGER.error("Login request failed", ar.cause());
                        promise.fail(ar.cause());
                    }
                });

        return promise.future();
    }

    public Future<Void> logout(String refreshToken) {
        String url = KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/logout";
        String formData = "client_id=" + CLIENT_ID +
                "&client_secret=" + CLIENT_SECRET +
                "&refresh_token=" + refreshToken;

        Promise<Void> promise = Promise.promise();

        webClient.postAbs(url)
                .putHeader("Content-Type", "application/x-www-form-urlencoded")
                .sendBuffer(Buffer.buffer(formData), ar -> {
                    if (ar.succeeded()) {
                        HttpResponse<Buffer> response = ar.result();
                        if (response.statusCode() == 204) {
                            LOGGER.info("Logout successful");
                            promise.complete();
                        } else {
                            LOGGER.errorf("Logout failed: %d - %s", response.statusCode(), response.bodyAsString());
                            promise.fail("Logout failed: " + response.statusCode());
                        }
                    } else {
                        LOGGER.error("Logout request failed", ar.cause());
                        promise.fail(ar.cause());
                    }
                });

        return promise.future();
    }

    private KeycloakUser createUserObject(RegisterRequest request) {
        KeycloakUser user = new KeycloakUser();

        user.setUsername(request.getEmail()); // Email = Username
        user.setEmail(request.getEmail());
        user.setEnabled(true);

        Credential credential = new Credential();
        credential.setType("password");
        credential.setValue(request.getPassword());
        credential.setTemporary(false);

        user.setCredentials(List.of(credential));

        return user;
    }


    public Future<String> createUser(KeycloakUser user) {
        String url = KEYCLOAK_URL + "/admin/realms/" + REALM + "/users";
        JsonObject newUserJson = JsonObject.mapFrom(user);

        return getAdminAccessToken().compose(token -> {
            Promise<String> promise = Promise.promise();

            webClient.postAbs(url)
                    .putHeader("Authorization", "Bearer " + token)
                    .putHeader("Content-Type", "application/json")
                    .as(BodyCodec.jsonObject())
                    .sendJsonObject(newUserJson, ar -> {
                        if (ar.succeeded()) {
                            HttpResponse<JsonObject> response = ar.result();
                            if (response.statusCode() == 201) {
                                String userId = extractUserIdFromLocationHeader(response);
                                promise.complete(userId);
                            } else {
                                LOGGER.errorf("Failed to create user: %d - %s",
                                        response.statusCode(), response.bodyAsString());
                                promise.fail("User creation failed: " + response.statusCode());
                            }
                        } else {
                            LOGGER.error("User creation request failed", ar.cause());
                            promise.fail(ar.cause());
                        }
                    });

            return promise.future();
        });
    }

    private String extractUserIdFromLocationHeader(HttpResponse<JsonObject> response) {
        String locationHeader = response.getHeader("Location");
        return locationHeader.replaceAll(".*/([^/]+)$", "$1");
    }

    public Future<Void> sendVerificationEmail(String userId) {
        String url = KEYCLOAK_URL + "/admin/realms/" + REALM + "/users/" + userId + "/send-verify-email";

        return getAdminAccessToken().compose(token -> {
            Promise<Void> promise = Promise.promise();

            webClient.putAbs(url)
                    .putHeader("Authorization", "Bearer " + token)
                    .putHeader("Content-Type", "application/json")
                    .send(ar -> {
                        if (ar.succeeded()) {
                            HttpResponse<Buffer> response = ar.result();
                            if (response.statusCode() == 204) {
                                LOGGER.info("Verification email sent successfully");
                                promise.complete();
                            } else {
                                LOGGER.errorf("Failed to send verification email: %d - %s",
                                        response.statusCode(), response.bodyAsString());
                                promise.fail("Verification email sending failed: " + response.statusCode());
                            }
                        } else {
                            LOGGER.error("Verification email request failed", ar.cause());
                            promise.fail(ar.cause());
                        }
                    });

            return promise.future();
        });
    }

    public Future<Void> sendPasswordResetEmail(String email) {
        return getAdminAccessToken()
                .compose(token -> findUserByEmail(email)
                        .compose(userId -> executePasswordResetEmail(token, userId))
                );
    }

    private Future<String> findUserByEmail(String email) {
        String url = KEYCLOAK_URL + "/admin/realms/" + REALM + "/users?email=" + email;

        return getAdminAccessToken().compose(token -> {
            Promise<String> promise = Promise.promise();

            webClient.getAbs(url)
                    .putHeader("Authorization", "Bearer " + token)
                    .as(BodyCodec.jsonArray())
                    .send(ar -> {
                        if (ar.succeeded()) {
                            if (!ar.result().body().isEmpty()) {
                                String userId = ar.result().body().getJsonObject(0).getString("id");
                                promise.complete(userId);
                            } else {
                                promise.fail("User not found");
                            }
                        } else {
                            promise.fail(ar.cause());
                        }
                    });

            return promise.future();
        });
    }

    private Future<Void> executePasswordResetEmail(String token, String userId) {
        String url = KEYCLOAK_URL + "/admin/realms/" + REALM +
                "/users/" + userId + "/execute-actions-email";

        Promise<Void> promise = Promise.promise();

        webClient.putAbs(url)
                .putHeader("Authorization", "Bearer " + token)
                .putHeader("Content-Type", "application/json")
                .sendJson(List.of("UPDATE_PASSWORD"), ar -> {
                    if (ar.succeeded() && ar.result().statusCode() == 204) {
                        promise.complete();
                    } else {
                        promise.fail("Password reset email failed");
                    }
                });

        return promise.future();
    }


    public Future<String> getAdminAccessToken() {
        String url = KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/token";

        String formData = "client_id=" + ADMIN_CLIENT_ID +
                "&client_secret=" + ADMIN_CLIENT_SECRET +
                "&grant_type=client_credentials";

        Promise<String> promise = Promise.promise();

        webClient.postAbs(url)
                .putHeader("Content-Type", "application/x-www-form-urlencoded")
                .sendBuffer(Buffer.buffer(formData), ar -> {
                    if (ar.succeeded()) {
                        HttpResponse<Buffer> response = ar.result();
                        if (response.statusCode() == 200) {
                            try {
                                JsonNode jsonNode = objectMapper.readTree(response.bodyAsString());
                                promise.complete(jsonNode.get("access_token").asText());
                            } catch (Exception e) {
                                LOGGER.error("Failed to parse access token JSON", e);
                                promise.fail("Access token parsing error");
                            }
                        } else {
                            LOGGER.errorf("Failed to get token: %d - %s",
                                    response.statusCode(), response.bodyAsString());
                            promise.fail("Token retrieval failed: " + response.statusCode());
                        }
                    } else {
                        LOGGER.error("Failed to retrieve access token", ar.cause());
                        promise.fail(ar.cause());
                    }
                });

        return promise.future();
    }


    // Add to KeycloakService class
    public Future<JsonObject> refreshToken(String refreshToken) {
        String url = KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/token";
        String formData = "client_id=" + CLIENT_ID +
                "&client_secret=" + CLIENT_SECRET +
                "&refresh_token=" + refreshToken +
                "&grant_type=refresh_token";

        Promise<JsonObject> promise = Promise.promise();

        webClient.postAbs(url)
                .putHeader("Content-Type", "application/x-www-form-urlencoded")
                .sendBuffer(Buffer.buffer(formData), ar -> {
                    if (ar.succeeded()) {
                        HttpResponse<Buffer> response = ar.result();
                        if (response.statusCode() == 200) {
                            JsonObject tokenResponse = response.bodyAsJsonObject();
                            promise.complete(tokenResponse);
                        } else {
                            LOGGER.errorf("Token refresh failed: %d - %s",
                                    response.statusCode(), response.bodyAsString());
                            promise.fail("Refresh failed: " + response.statusCode());
                        }
                    } else {
                        LOGGER.error("Refresh token request failed", ar.cause());
                        promise.fail(ar.cause());
                    }
                });

        return promise.future();
    }


}
