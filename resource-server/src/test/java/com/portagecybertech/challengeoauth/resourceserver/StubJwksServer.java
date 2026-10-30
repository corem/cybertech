package com.portagecybertech.challengeoauth.resourceserver;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;

/**
 * Real JWKS server over HTTP: the test goes through the actual key retrieval mechanism.
 */
final class StubJwksServer {

    private final HttpServer server;

    private final AtomicInteger fetchCount = new AtomicInteger();

    private volatile JWKSet published = new JWKSet();

    StubJwksServer() {
        try {
            this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        this.server.createContext("/jwks.json", (exchange) -> {
            this.fetchCount.incrementAndGet();
            byte[] body = this.published.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        this.server.start();
    }

    String url() {
        return "http://localhost:" + this.server.getAddress().getPort() + "/jwks.json";
    }

    void publish(RSAKey... keys) {
        this.published = new JWKSet(List.<JWK>of(keys)).toPublicJWKSet();
    }

    int fetchCount() {
        return this.fetchCount.get();
    }

}
