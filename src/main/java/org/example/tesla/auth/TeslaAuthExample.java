package org.example.tesla.auth;

import java.io.IOException;
import java.util.Scanner;

/**
 * Example usage of the updated TeslaTokenService with OAuth 2.0 Authorization Code flow.
 * 
 * This example demonstrates the complete OAuth flow:
 * 1. Generate authorization URL
 * 2. User visits URL and authorizes
 * 3. Exchange authorization code for tokens
 * 4. Refresh tokens when needed
 */
public class TeslaAuthExample {

    public static void main(String[] args) {
        TeslaTokenService tokenService = new TeslaTokenService();
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.println("Tesla OAuth 2.0 Authentication Example");
            System.out.println("=====================================");
            
            // Step 1: Generate authorization URL
            TeslaTokenService.AuthorizationResult authResult = tokenService.getAuthorizationUrl();
            String authUrl = authResult.getAuthorizationUrl();
            String state = authResult.getState();
            
            System.out.println("\n1. Visit this URL in your browser to authorize:");
            System.out.println(authUrl);
            
            System.out.println("\n2. After authorization, you'll be redirected to a URL like:");
            System.out.println("https://auth.tesla.com/void/callback?code=AUTHORIZATION_CODE&state=" + state);
            
            System.out.println("\n3. Extract the authorization code from the URL and enter it below:");
            System.out.print("Authorization Code: ");
            String authCode = scanner.nextLine().trim();
            
            // Step 4: Exchange the authorization code for tokens
            System.out.println("\n4. Exchanging authorization code for tokens...");
            TeslaTokenService.Tokens tokens = tokenService.exchangeCodeForTokensWithState(authCode, state);
            
            System.out.println("\n✅ Authentication successful!");
            System.out.println("Access Token: " + tokens.getAccessToken().substring(0, Math.min(20, tokens.getAccessToken().length())) + "...");
            System.out.println("Refresh Token: " + tokens.getRefreshToken().substring(0, Math.min(20, tokens.getRefreshToken().length())) + "...");
            System.out.println("Token Type: " + tokens.getTokenType());
            System.out.println("Expires In: " + tokens.getExpiresInSeconds() + " seconds");
            System.out.println("Created At: " + tokens.getCreatedAtEpochSeconds());
            
            // Step 5: Demonstrate token refresh
            System.out.println("\n5. Demonstrating token refresh...");
            TeslaTokenService.Tokens newTokens = tokenService.refreshTokens(tokens.getRefreshToken());
            System.out.println("✅ Token refresh successful!");
            System.out.println("New Access Token: " + newTokens.getAccessToken().substring(0, Math.min(20, newTokens.getAccessToken().length())) + "...");
            
            System.out.println("\n🎉 OAuth flow completed successfully!");
            System.out.println("\nYou can now use the access token to make Tesla API calls.");
            System.out.println("Remember to refresh the token before it expires.");
            
        } catch (TeslaTokenService.TeslaTokenServiceException e) {
            System.err.println("Tesla Authentication Error: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
