package org.example.tesla.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tesla API token service using OAuth 2.0 Authorization Code flow with PKCE.
 * This replaces the deprecated password grant flow.
 */
public class TeslaTokenService {

    private static final URI AUTH_ENDPOINT = URI.create("https://auth.tesla.com/oauth2/v3/authorize");
    private static final URI TOKEN_ENDPOINT = URI.create("https://auth.tesla.com/oauth2/v3/token");
    private static final String CLIENT_ID = "ownerapi";
    private static final String REDIRECT_URI = "https://auth.tesla.com/void/callback";
    private static final String SCOPE = "openid email offline_access";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Map<String, PKCEPair> pkceStore = new ConcurrentHashMap<>();

    public TeslaTokenService() {
        this(HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .build(), new ObjectMapper());
    }

    public TeslaTokenService(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    /**
     * Generate PKCE code verifier and challenge
     */
    private PKCEPair generatePKCE() throws TeslaTokenServiceException {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] codeVerifierBytes = new byte[32];
            secureRandom.nextBytes(codeVerifierBytes);
            String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierBytes);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

            return new PKCEPair(codeVerifier, codeChallenge);
        } catch (NoSuchAlgorithmException e) {
            throw new TeslaTokenServiceException("Failed to generate PKCE", e);
        }
    }

    /**
     * Get the authorization URL for the user to visit
     * @return AuthorizationResult containing the URL and state for later use
     */
    public AuthorizationResult getAuthorizationUrl() throws TeslaTokenServiceException {
        try {
            PKCEPair pkce = generatePKCE();
            String state = generateRandomState();
            
            // Store PKCE and state for later retrieval
            pkceStore.put(state, pkce);
            
            String authUrl = String.format("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
                    AUTH_ENDPOINT.toString(),
                    CLIENT_ID,
                    REDIRECT_URI,
                    SCOPE,
                    state,
                    pkce.codeChallenge);
            
            return new AuthorizationResult(authUrl, state);
        } catch (Exception e) {
            throw new TeslaTokenServiceException("Failed to generate authorization URL", e);
        }
    }

    /**
     * Exchange authorization code for tokens using stored PKCE
     */
    public Tokens exchangeCodeForTokensWithState(String authorizationCode, String state) throws IOException, InterruptedException, TeslaTokenServiceException {
        PKCEPair pkce = pkceStore.get(state);
        if (pkce == null) {
            throw new TeslaTokenServiceException("Invalid or expired state parameter. Please generate a new authorization URL.");
        }
        
        // Remove the PKCE from store after use
        pkceStore.remove(state);
        
        return exchangeCodeForTokens(authorizationCode, pkce.codeVerifier);
    }

    /**
     * Exchange authorization code for tokens with explicit code verifier
     */
    public Tokens exchangeCodeForTokens(String authorizationCode, String codeVerifier) throws IOException, InterruptedException, TeslaTokenServiceException {
        String body = String.format("grant_type=authorization_code&client_id=%s&code=%s&redirect_uri=%s&code_verifier=%s",
                CLIENT_ID,
                authorizationCode,
                REDIRECT_URI,
                codeVerifier);

        HttpRequest request = HttpRequest.newBuilder(TOKEN_ENDPOINT)
                .timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
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

    /**
     * Refresh access token using refresh token
     */
    public Tokens refreshTokens(String refreshToken) throws IOException, InterruptedException, TeslaTokenServiceException {
        String body = String.format("grant_type=refresh_token&client_id=%s&refresh_token=%s&scope=%s",
                CLIENT_ID,
                refreshToken,
                SCOPE);

        HttpRequest request = HttpRequest.newBuilder(TOKEN_ENDPOINT)
                .timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            JsonNode node = objectMapper.readTree(response.body());
            String newAccessToken = getRequired(node, "access_token");
            String newRefreshToken = node.has("refresh_token") ? node.get("refresh_token").asText() : refreshToken;
            long expiresIn = node.has("expires_in") ? node.get("expires_in").asLong() : -1L;
            String tokenType = node.has("token_type") ? node.get("token_type").asText() : "Bearer";
            long createdAt = node.has("created_at") ? node.get("created_at").asLong() : System.currentTimeMillis() / 1000L;
            return new Tokens(newAccessToken, newRefreshToken, tokenType, expiresIn, createdAt);
        }

        String msg = "Token refresh failed: HTTP " + response.statusCode() + ": " + response.body();
        throw new TeslaTokenServiceException(msg);
    }

    private String generateRandomState() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] stateBytes = new byte[16];
        secureRandom.nextBytes(stateBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(stateBytes);
    }

    private static String getRequired(JsonNode node, String field) throws TeslaTokenServiceException {
        if (!node.hasNonNull(field)) {
            throw new TeslaTokenServiceException("Missing field in response: " + field);
        }
        return node.get(field).asText();
    }

    public static class AuthorizationResult {
        private final String authorizationUrl;
        private final String state;

        public AuthorizationResult(String authorizationUrl, String state) {
            this.authorizationUrl = authorizationUrl;
            this.state = state;
        }

        public String getAuthorizationUrl() {
            return authorizationUrl;
        }

        public String getState() {
            return state;
        }
    }

    public static class PKCEPair {
        private final String codeVerifier;
        private final String codeChallenge;

        public PKCEPair(String codeVerifier, String codeChallenge) {
            this.codeVerifier = codeVerifier;
            this.codeChallenge = codeChallenge;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public String getCodeChallenge() {
            return codeChallenge;
        }
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

        public TeslaTokenServiceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}


