package com.myapp.auth.adapter;

import com.myapp.auth.adapter.FakeKeycloak.Reply;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Der Kern: die App darf nur dann ausloggen, wenn Keycloak den Refresh Token
 * wirklich abgelehnt hat (400 + session_expired=true). Jeder andere Fehler ist
 * voruebergehend (503) - frueher kam auch dafuer "400 invalid_grant".
 */
@QuarkusTest
@QuarkusTestResource(FakeKeycloak.class)
class AuthResourceTest {

    @BeforeEach
    void resetKeycloak() {
        FakeKeycloak.reset();
    }

    // --- /users/refresh ------------------------------------------------------

    @Test
    void refresh_liefertNeueTokens() {
        given().contentType(ContentType.JSON).body(Map.of("refreshToken", "old-refresh"))
                .when().post("/users/refresh")
                .then().statusCode(200)
                .body("access_token", equalTo("access-1"))
                .body("refresh_token", equalTo("refresh-1"));

        Map<String, String> form = FakeKeycloak.tokenRequests.get(0);
        assertEquals("refresh_token", form.get("grant_type"));
        assertEquals("old-refresh", form.get("refresh_token"));
        assertEquals("recipeapp", form.get("client_id"));
        assertEquals("client-secret", form.get("client_secret"));
    }

    @Test
    void refresh_keycloakLehntTokenAb_400UndSessionExpired() {
        FakeKeycloak.onToken = form -> Reply.error(400, "invalid_grant", "Token is not active");

        given().contentType(ContentType.JSON).body(Map.of("refreshToken", "expired"))
                .when().post("/users/refresh")
                .then().statusCode(400)
                .body("error", equalTo("invalid_grant"))
                .body("error_description", equalTo("Refresh failed: 400"))
                .body("session_expired", equalTo(true));
    }

    @Test
    void refresh_keycloakNichtErreichbar_503StattLogout() {
        FakeKeycloak.onToken = form -> Reply.noResponse();

        given().contentType(ContentType.JSON).body(Map.of("refreshToken", "still-valid"))
                .when().post("/users/refresh")
                .then().statusCode(503)
                .body("error", equalTo("temporarily_unavailable"))
                .body("session_expired", equalTo(false));
    }

    @Test
    void refresh_keycloakInternerFehler_503StattLogout() {
        FakeKeycloak.onToken = form -> new Reply(500, "Internal Server Error");

        given().contentType(ContentType.JSON).body(Map.of("refreshToken", "still-valid"))
                .when().post("/users/refresh")
                .then().statusCode(503)
                .body("session_expired", equalTo(false));
    }

    @Test
    void refresh_falschesClientSecret_istKeinGrundZumAusloggen() {
        // Keycloak lehnt hier UNS ab, nicht den Nutzer.
        FakeKeycloak.onToken = form -> Reply.error(401, "unauthorized_client", "Invalid client or Invalid client credentials");

        given().contentType(ContentType.JSON).body(Map.of("refreshToken", "still-valid"))
                .when().post("/users/refresh")
                .then().statusCode(503)
                .body("session_expired", equalTo(false));
    }

    @Test
    void refresh_ohneToken_400AberKeinSessionExpired() {
        given().contentType(ContentType.JSON).body(Map.of())
                .when().post("/users/refresh")
                .then().statusCode(400)
                .body("error", equalTo("invalid_request"))
                .body("session_expired", equalTo(false));

        assertEquals(0, FakeKeycloak.tokenRequests.size());
    }

    // --- /users/login --------------------------------------------------------

    @Test
    void login_fragtOfflineTokenAn() {
        given().contentType(ContentType.JSON).body(Map.of("username", "anna@example.org", "password", "geheim"))
                .when().post("/users/login")
                .then().statusCode(200)
                .body("refresh_token", equalTo("refresh-1"));

        Map<String, String> form = FakeKeycloak.tokenRequests.get(0);
        assertEquals("password", form.get("grant_type"));
        assertEquals("offline_access", form.get("scope"));
    }

    @Test
    void login_sonderzeichenKommenUnveraendertAn() {
        // Ohne URL-Kodierung wurde aus "+" ein Leerzeichen und "&" trennte ein
        // neues Feld ab - solche Passwoerter konnten sich nie einloggen.
        String username = "anna+rezepte@example.org";
        String password = "p&ss+w%rd=1 #\u00e4";

        given().contentType(ContentType.JSON).body(Map.of("username", username, "password", password))
                .when().post("/users/login")
                .then().statusCode(200);

        Map<String, String> form = FakeKeycloak.tokenRequests.get(0);
        assertEquals(username, form.get("username"));
        assertEquals(password, form.get("password"));
        assertEquals("password", form.get("grant_type"));
    }

    @Test
    void login_falschesPasswort_401() {
        FakeKeycloak.onToken = form -> Reply.error(401, "invalid_grant", "Invalid user credentials");

        given().contentType(ContentType.JSON).body(Map.of("username", "anna@example.org", "password", "falsch"))
                .when().post("/users/login")
                .then().statusCode(401)
                .body("error", equalTo("invalid_grant"))
                .body("error_description", equalTo("Login failed: 401"));
    }

    @Test
    void login_keycloakNichtErreichbar_503StattFalschesPasswort() {
        FakeKeycloak.onToken = form -> Reply.noResponse();

        given().contentType(ContentType.JSON).body(Map.of("username", "anna@example.org", "password", "geheim"))
                .when().post("/users/login")
                .then().statusCode(503)
                .body("error", equalTo("temporarily_unavailable"));
    }

    @Test
    void login_scopeImRealmNichtErlaubt_loggtOhneScopeEin() {
        FakeKeycloak.onToken = form -> form.containsKey("scope")
                ? Reply.error(400, "invalid_scope", "Invalid scopes: offline_access")
                : Reply.ok();

        given().contentType(ContentType.JSON).body(Map.of("username", "anna@example.org", "password", "geheim"))
                .when().post("/users/login")
                .then().statusCode(200)
                .body("access_token", equalTo("access-1"));

        assertEquals(2, FakeKeycloak.tokenRequests.size());
        assertEquals("offline_access", FakeKeycloak.tokenRequests.get(0).get("scope"));
        assertNull(FakeKeycloak.tokenRequests.get(1).get("scope"));
    }

    @Test
    void login_falschesPasswort_wirdNichtOhneScopeWiederholt() {
        FakeKeycloak.onToken = form -> Reply.error(401, "invalid_grant", "Invalid user credentials");

        given().contentType(ContentType.JSON).body(Map.of("username", "anna@example.org", "password", "falsch"))
                .when().post("/users/login")
                .then().statusCode(401);

        assertEquals(1, FakeKeycloak.tokenRequests.size());
    }

    // --- /users/logout -------------------------------------------------------

    @Test
    void logout_gehtOhneAccessToken_undBeendetDieSessionBeiKeycloak() {
        given().contentType(ContentType.JSON).body(Map.of("refreshToken", "refresh-1"))
                .when().post("/users/logout")
                .then().statusCode(200);

        assertEquals("refresh-1", FakeKeycloak.logoutRequests.get(0).get("refresh_token"));
    }

    @Test
    void logout_tokenSchonUngueltig_istTrotzdemErfolg() {
        FakeKeycloak.logoutStatus = 400;

        given().contentType(ContentType.JSON).body(Map.of("refreshToken", "already-gone"))
                .when().post("/users/logout")
                .then().statusCode(200);
    }

    @Test
    void geschuetzteEndpunkteBleibenGeschuetzt() {
        given().when().get("/users/me").then().statusCode(401);
        assertFalse(FakeKeycloak.tokenRequests.stream().anyMatch(f -> true));
    }
}
