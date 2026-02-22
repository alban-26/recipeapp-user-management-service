package com.myapp.auth.adapter;


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
                    Map<String, String> errorResponse = new HashMap<>();
                    errorResponse.put("error", "invalid_grant");
                    errorResponse.put("error_description", error.getMessage());
                    asyncResponse.resume(Response.status(Response.Status.UNAUTHORIZED).entity(errorResponse).build());
                });
    }


    @POST
    @Path("/logout")
    public void logout(LogoutRequest request, @Suspended AsyncResponse asyncResponse) {
        keycloakService.logout(request.getRefreshToken())
                .onSuccess(v -> asyncResponse.resume(Response.ok("Logout successful").build()))
                .onFailure(error -> asyncResponse.resume(Response.status(Response.Status.BAD_REQUEST)
                        .entity("Error: " + error.getMessage()).build()));
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
        keycloakService.refreshToken(request.getRefreshToken())
                .onSuccess(tokenResponse -> asyncResponse.resume(Response.ok(tokenResponse).build()))
                .onFailure(error -> {
                    Map<String, String> errorResponse = new HashMap<>();
                    errorResponse.put("error", "invalid_grant");
                    errorResponse.put("error_description", error.getMessage());
                    asyncResponse.resume(Response.status(Response.Status.BAD_REQUEST).entity(errorResponse).build());
                });
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
