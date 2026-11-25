package com.myapp.auth.adapter;


import com.myapp.auth.application.KeycloakException;
import com.myapp.auth.application.KeycloakService;
import com.myapp.auth.domain.*;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.common.annotation.NonBlocking;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.container.AsyncResponse;
import jakarta.ws.rs.container.Suspended;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Path("/users")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@NonBlocking
public class AuthResource {

    @Inject
    KeycloakService keycloakService;
    @Inject
    SecurityIdentity securityIdentity;

    @POST
    @Path("/register")
    public void registerUser(RegisterRequest request, @Suspended AsyncResponse asyncResponse) {
        keycloakService.registerUser(request)
                .onSuccess(v -> asyncResponse.resume(Response.ok("User registered successfully").build()))
                .onFailure(error -> asyncResponse.resume(Response.status(Response.Status.BAD_REQUEST)
                        .entity("Error: " + error.getMessage()).build()));
    }


    @POST
    @Path("/login")
    public void login(LoginRequest request, @Suspended AsyncResponse asyncResponse) {
        securityIdentity.getPrincipal();
        keycloakService.login(request.getUsername(), request.getPassword())
                .onSuccess(tokenResponse -> asyncResponse.resume(Response.ok(tokenResponse).build()))
                .onFailure(error -> {
                    // 401 nur, wenn Keycloak die Zugangsdaten wirklich abgelehnt hat.
                    // Ist Keycloak nicht erreichbar oder falsch konfiguriert, ist das
                    // kein "falsches Passwort", sondern ein 503.
                    if (isGrantRejected(error)) {
                        asyncResponse.resume(Response.status(Response.Status.UNAUTHORIZED)
                                .entity(errorBody("invalid_grant", "Login failed: " + statusOf(error), false))
                                .build());
                    } else {
                        asyncResponse.resume(unavailable("Login failed: " + describe(error)));
                    }
                });
    }


    @POST
    @Path("/logout")
    public void logout(LogoutRequest request, @Suspended AsyncResponse asyncResponse) {
        if (request == null || isBlank(request.getRefreshToken())) {
            asyncResponse.resume(Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorBody("invalid_request", "refreshToken is missing", false)).build());
            return;
        }
        keycloakService.logout(request.getRefreshToken())
                .onSuccess(v -> asyncResponse.resume(Response.ok("Logout successful").build()))
                .onFailure(error -> asyncResponse.resume(unavailable("Logout failed: " + describe(error))));
    }


    @GET
    @Path("/me")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserInfo() {
        Principal principal = securityIdentity.getPrincipal();
        if (principal instanceof JsonWebToken jwt) {
            String userId = jwt.getSubject();
            String email = jwt.getClaim("email");

            Boolean emailVerified = (Boolean) jwt.getClaim("email_verified");
            emailVerified = (emailVerified != null) ? emailVerified : false;

            String firstName = jwt.getClaim("given_name");
            String lastName = jwt.getClaim("family_name");

            return Response.ok(new UserInfoResponse(userId, email, firstName, lastName)).build();
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }



    @POST
    @Path("/refresh")
    public void refreshToken(RefreshTokenRequest request, @Suspended AsyncResponse asyncResponse) {
        if (request == null || isBlank(request.getRefreshToken())) {
            asyncResponse.resume(Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorBody("invalid_request", "refreshToken is missing", false)).build());
            return;
        }
        keycloakService.refreshToken(request.getRefreshToken())
                .onSuccess(tokenResponse -> asyncResponse.resume(Response.ok(tokenResponse).build()))
                .onFailure(error -> {
                    // ACHTUNG, Vertrag mit der App: 400 + invalid_grant bedeutet
                    // "Refresh Token endgueltig ungueltig" - die App loggt dann aus.
                    // Das darf NUR passieren, wenn Keycloak den Token wirklich
                    // abgelehnt hat. Frueher kam hier fuer JEDEN Fehler 400, also
                    // auch wenn Keycloak kurz nicht erreichbar war - und jeder
                    // Nutzer, dessen Access Token gerade ablief, flog raus.
                    if (isGrantRejected(error)) {
                        asyncResponse.resume(Response.status(Response.Status.BAD_REQUEST)
                                .entity(errorBody("invalid_grant", "Refresh failed: " + statusOf(error), true))
                                .build());
                    } else {
                        asyncResponse.resume(unavailable("Refresh failed: " + describe(error)));
                    }
                });
    }

    private static boolean isGrantRejected(Throwable error) {
        return error instanceof KeycloakException ke && ke.isGrantRejected();
    }

    private static int statusOf(Throwable error) {
        return error instanceof KeycloakException ke ? ke.getStatus() : 0;
    }

    /** Kurzbeschreibung fuers Log des Clients - ohne Interna wie Hostnamen. */
    private static String describe(Throwable error) {
        if (error instanceof KeycloakException ke && !ke.isTransportFailure()) {
            return String.valueOf(ke.getStatus());
        }
        return "auth server unreachable";
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static Map<String, Object> errorBody(String error, String description, boolean sessionExpired) {
        Map<String, Object> body = new HashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        body.put("session_expired", sessionExpired);
        return body;
    }

    /** Voruebergehender Fehler: der Client behaelt seine Session und versucht es spaeter erneut. */
    private static Response unavailable(String description) {
        return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                .entity(errorBody("temporarily_unavailable", description, false))
                .build();
    }

    @POST
    @Path("/forgot-password")
    public void forgotPassword(ForgotPasswordRequest request,
                               @Suspended AsyncResponse asyncResponse) {

        keycloakService.sendPasswordResetEmail(request.getEmail())
                .recover(error -> {
                    return io.vertx.core.Future.succeededFuture();
                })
                .onComplete(ar -> {
                    Map<String, String> response = new HashMap<>();
                    response.put("message",
                            "If the email exists, a password reset link has been sent.");
                    asyncResponse.resume(Response.ok(response).build());
                });
    }


}
