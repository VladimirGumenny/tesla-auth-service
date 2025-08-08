package org.example.tesla.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Minimal helper to obtain Tesla API tokens using the legacy password grant.
 * Note: This flow may fail for accounts with MFA and may be blocked by Tesla.
 * Prefer the OAuth Authorization Code with PKCE flow for production use.
 */
public class TeslaTokenService {

    private static final URI TOKEN_ENDPOINT = URI.create("https://owner-api.teslamotors.com/oauth/token");
    private static final String CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384";
    private static final String CLIENT_SECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public TeslaTokenService() {
        this(HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .build(), new ObjectMapper());
    }

    public TeslaTokenService(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    public Tokens fetchTokensWithPasswordGrant(String email, String password) throws IOException, InterruptedException, TeslaTokenServiceException {
        String body = "{\"grant_type\":\"password\"," +
                "\"client_id\":\"" + CLIENT_ID + "\"," +
                "\"client_secret\":\"" + CLIENT_SECRET + "\"," +
                "\"email\":\"" + escapeJson(email) + "\"," +
                "\"password\":\"" + escapeJson(password) + "\"}";

        HttpRequest request = HttpRequest.newBuilder(TOKEN_ENDPOINT)
                .timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            JsonNode node = objectMapper.readTree(response.body());
            String accessToken = getRequired(node, "access_token");
            String refreshToken = getRequired(node, "refresh_token");
            long expiresIn = node.has("expires_in") ? node.get("expires_in").asLong() : -1L;
            String tokenType = node.has("token_type") ? node.get("token_type").asText() : "Bearer";
            long createdAt = node.has("created_at") ? node.get("created_at").asLong() : System.currentTimeMillis() / 1000L;
            return new Tokens(accessToken, refreshToken, tokenType, expiresIn, createdAt);
        }

        String msg = "Token request failed: HTTP " + response.statusCode() + ": " + response.body();
        throw new TeslaTokenServiceException(msg);
    }

    private static String getRequired(JsonNode node, String field) throws TeslaTokenServiceException {
        if (!node.hasNonNull(field)) {
            throw new TeslaTokenServiceException("Missing field in response: " + field);
        }
        return node.get(field).asText();
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public static class Tokens {
        private final String accessToken;
        private final String refreshToken;
        private final String tokenType;
        private final long expiresInSeconds;
        private final long createdAtEpochSeconds;

        public Tokens(String accessToken, String refreshToken, String tokenType, long expiresInSeconds, long createdAtEpochSeconds) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.tokenType = tokenType;
            this.expiresInSeconds = expiresInSeconds;
            this.createdAtEpochSeconds = createdAtEpochSeconds;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public String getTokenType() {
            return tokenType;
        }

        public long getExpiresInSeconds() {
            return expiresInSeconds;
        }

        public long getCreatedAtEpochSeconds() {
            return createdAtEpochSeconds;
        }
    }

    public static class TeslaTokenServiceException extends Exception {
        public TeslaTokenServiceException(String message) {
            super(message);
        }
    }
}


