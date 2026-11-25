package com.myapp.auth.adapter;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * Minimaler Keycloak-Ersatz fuer Tests: Token- und Logout-Endpunkt, dazu das
 * Noetigste, damit quarkus-oidc beim Start zufrieden ist.
 *
 * Das Verhalten des Token-Endpunkts legt jeder Test ueber {@link #onToken} fest.
 */
public class FakeKeycloak implements QuarkusTestResourceLifecycleManager {

    /** Antwort des Token-Endpunkts. status &lt;= 0 bedeutet: Verbindung ohne Antwort schliessen. */
    public record Reply(int status, String body) {
        public static Reply ok() {
            return new Reply(200, "{\"access_token\":\"access-1\",\"refresh_token\":\"refresh-1\",\"expires_in\":300}");
        }

        public static Reply error(int status, String error, String description) {
            return new Reply(status, "{\"error\":\"" + error + "\",\"error_description\":\"" + description + "\"}");
        }

        public static Reply noResponse() {
            return new Reply(-1, "");
        }
    }

    /** Bekommt die (URL-dekodierten) Formularfelder der Anfrage. */
    public static volatile Function<Map<String, String>, Reply> onToken = form -> Reply.ok();
    public static volatile int logoutStatus = 204;

    public static final List<Map<String, String>> tokenRequests = new CopyOnWriteArrayList<>();
    public static final List<Map<String, String>> logoutRequests = new CopyOnWriteArrayList<>();

    private HttpServer server;

    public static void reset() {
        onToken = form -> Reply.ok();
        logoutStatus = 204;
        tokenRequests.clear();
        logoutRequests.clear();
    }

    @Override
    public Map<String, String> start() {
        try {
            server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        String base = "http://localhost:" + server.getAddress().getPort();
        String realm = base + "/realms/recipeapp";
        String oidc = "/realms/recipeapp/protocol/openid-connect";

        server.createContext("/realms/recipeapp/.well-known/openid-configuration", exchange ->
                respond(exchange, 200, "{\"issuer\":\"" + realm + "\","
                        + "\"jwks_uri\":\"" + realm + "/protocol/openid-connect/certs\","
                        + "\"token_endpoint\":\"" + realm + "/protocol/openid-connect/token\","
                        + "\"authorization_endpoint\":\"" + realm + "/protocol/openid-connect/auth\"}"));
        server.createContext(oidc + "/certs", exchange -> respond(exchange, 200, "{\"keys\":[]}"));

        server.createContext(oidc + "/token", exchange -> {
            Map<String, String> form = readForm(exchange);
            tokenRequests.add(form);
            Reply reply = onToken.apply(form);
            if (reply.status() <= 0) {
                exchange.close();
                return;
            }
            respond(exchange, reply.status(), reply.body());
        });

        server.createContext(oidc + "/logout", exchange -> {
            logoutRequests.add(readForm(exchange));
            if (logoutStatus == 204) {
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
            } else {
                respond(exchange, logoutStatus, "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid refresh token\"}");
            }
        });
        server.start();

        Map<String, String> config = new HashMap<>();
        config.put("keycloak.url", base);
        config.put("keycloak.client-secret", "client-secret");
        config.put("keycloak.admin.client-secret", "admin-secret");
        config.put("keycloak.request-timeout-ms", "2000");
        config.put("quarkus.oidc.auth-server-url", realm);
        config.put("quarkus.oidc.token.issuer", realm);
        config.put("quarkus.oidc.credentials.secret", "client-secret");
        config.put("quarkus.log.handler.gelf.enabled", "false");
        return config;
    }

    @Override
    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static Map<String, String> readForm(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> form = new HashMap<>();
        for (String pair : body.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            form.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return form;
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
