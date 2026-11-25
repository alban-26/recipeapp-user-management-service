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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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

    /**
     * Scope fuer den Login. Mit "offline_access" stellt Keycloak einen Offline
     * Token aus: der Refresh Token haengt dann nicht mehr an der SSO-Session
     * (Standard: 30 Minuten Leerlauf, maximal 10 Stunden) und ueberlebt auch
     * einen Keycloak-Neustart. Leer lassen = bisheriges Verhalten.
     */
    @ConfigProperty(name = "keycloak.login-scope")
    Optional<String> LOGIN_SCOPE;

    /** Nach dieser Zeit gilt ein Keycloak-Aufruf als fehlgeschlagen (statt ewig zu haengen). */
    @ConfigProperty(name = "keycloak.request-timeout-ms", defaultValue = "10000")
    long REQUEST_TIMEOUT_MS;

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
        String scope = LOGIN_SCOPE.map(String::trim).filter(s -> !s.isEmpty()).orElse(null);

        Future<JsonObject> attempt = requestToken(passwordGrant(username, password, scope), "Login");
        if (scope == null) {
            return attempt;
        }

        // Ist der Scope im Realm nicht freigeschaltet, darf deswegen niemand
        // ausgesperrt werden: dann wie bisher ohne Scope einloggen.
        return attempt.recover(error -> {
            if (error instanceof KeycloakException ke && ke.isScopeRejected()) {
                LOGGER.warnf("Keycloak lehnt Scope '%s' ab (%s: %s) - Login ohne Scope. "
                                + "Client-Scope und Rolle 'offline_access' im Realm pruefen.",
                        scope, ke.getError(), ke.getMessage());
                return requestToken(passwordGrant(username, password, null), "Login");
            }
            return Future.failedFuture(error);
        });
    }

    public Future<Void> logout(String refreshToken) {
        String url = KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/logout";
        Map<String, String> form = clientCredentials();
        form.put("refresh_token", refreshToken);

        Promise<Void> promise = Promise.promise();

        webClient.postAbs(url)
                .timeout(REQUEST_TIMEOUT_MS)
                .putHeader("Content-Type", "application/x-www-form-urlencoded")
                .sendBuffer(formBody(form), ar -> {
                    if (ar.failed()) {
                        LOGGER.error("Logout request failed", ar.cause());
                        promise.fail(new KeycloakException(0, null, messageOf(ar.cause()), ar.cause()));
                        return;
                    }
                    HttpResponse<Buffer> response = ar.result();
                    if (response.statusCode() == 204) {
                        LOGGER.info("Logout successful");
                        promise.complete();
                    } else if (response.statusCode() == 400) {
                        // Token war schon ungueltig - die Session ist also bereits beendet.
                        LOGGER.infof("Logout: Token bereits ungueltig - %s", response.bodyAsString());
                        promise.complete();
                    } else {
                        LOGGER.errorf("Logout failed: %d - %s", response.statusCode(), response.bodyAsString());
                        promise.fail(toException(response, "Logout failed: " + response.statusCode()));
                    }
                });

        return promise.future();
    }

    private Map<String, String> clientCredentials() {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("client_id", CLIENT_ID);
        form.put("client_secret", CLIENT_SECRET);
        return form;
    }

    private Map<String, String> passwordGrant(String username, String password, String scope) {
        Map<String, String> form = clientCredentials();
        form.put("grant_type", "password");
        form.put("username", username);
        form.put("password", password);
        if (scope != null) {
            form.put("scope", scope);
        }
        return form;
    }

    /**
     * Baut den Formular-Body und kodiert dabei jeden Wert. Vorher wurden die
     * Werte roh aneinandergehaengt: ein "+" im Passwort kam als Leerzeichen
     * an, ein "&amp;" begann ein neues Feld - solche Zugangsdaten konnten sich
     * nie einloggen.
     *
     * Bewusst von Hand statt ueber WebClient.sendForm(): das setzt voraus, dass
     * der Aufruf auf dem Vert.x-Kontext des Clients laeuft, und der WebClient
     * hier haengt an einer eigenen Vert.x-Instanz (siehe WebClientProducer).
     */
    private static Buffer formBody(Map<String, String> fields) {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> field : fields.entrySet()) {
            if (body.length() > 0) {
                body.append('&');
            }
            String value = field.getValue() == null ? "" : field.getValue();
            body.append(URLEncoder.encode(field.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
        return Buffer.buffer(body.toString());
    }

    /**
     * POST auf den Token-Endpunkt. Schlaegt mit einer {@link KeycloakException}
     * fehl, an der man erkennt, OB Keycloak geantwortet hat und WAS es gesagt hat.
     */
    private Future<JsonObject> requestToken(Map<String, String> form, String what) {
        String url = KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/token";

        Promise<JsonObject> promise = Promise.promise();

        webClient.postAbs(url)
                .timeout(REQUEST_TIMEOUT_MS)
                .putHeader("Content-Type", "application/x-www-form-urlencoded")
                .sendBuffer(formBody(form), ar -> {
                    if (ar.failed()) {
                        LOGGER.errorf(ar.cause(), "%s: Keycloak nicht erreichbar", what);
                        promise.fail(new KeycloakException(0, null, messageOf(ar.cause()), ar.cause()));
                        return;
                    }
                    HttpResponse<Buffer> response = ar.result();
                    if (response.statusCode() == 200) {
                        try {
                            promise.complete(response.bodyAsJsonObject());
                        } catch (RuntimeException e) {
                            LOGGER.errorf(e, "%s: Antwort von Keycloak nicht lesbar", what);
                            promise.fail(new KeycloakException(502, null, "Unreadable token response", e));
                        }
                        return;
                    }
                    LOGGER.errorf("%s failed: %d - %s", what, response.statusCode(), response.bodyAsString());
                    promise.fail(toException(response, what + " failed: " + response.statusCode()));
                });

        return promise.future();
    }

    private static KeycloakException toException(HttpResponse<Buffer> response, String fallbackMessage) {
        String error = null;
        String description = null;
        try {
            JsonObject body = response.bodyAsJsonObject();
            if (body != null) {
                error = body.getString("error");
                description = body.getString("error_description");
            }
        } catch (RuntimeException ignored) {
            // kein JSON (z.B. HTML-Fehlerseite eines Proxys)
        }
        return new KeycloakException(response.statusCode(), error,
                description != null ? description : fallbackMessage, null);
    }

    private static String messageOf(Throwable cause) {
        return cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
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


    public Future<JsonObject> refreshToken(String refreshToken) {
        Map<String, String> form = clientCredentials();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        return requestToken(form, "Token refresh");
    }


}
