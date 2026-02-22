package com.myapp.auth.application;

import io.vertx.core.Vertx;
import io.vertx.ext.web.client.WebClient;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

@ApplicationScoped
public class WebClientProducer {

    @Produces
    @ApplicationScoped
    public WebClient createWebClient() {
        return WebClient.create(Vertx.vertx());
    }
}
