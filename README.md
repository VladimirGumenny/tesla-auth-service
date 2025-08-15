# Tesla Authentication Service

A Java service for obtaining Tesla API access tokens and refresh tokens using OAuth 2.0 Authorization Code flow with PKCE.

## ⚠️ Important Update

**The previous password-based authentication has been deprecated by Tesla.** This service now uses the current OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange) as required by Tesla's updated API.

## ⚠️ Critical PKCE Requirement

**IMPORTANT**: Each authorization code is cryptographically bound to its specific PKCE code verifier. You MUST use the authorization code with the same PKCE code verifier that was used to generate the authorization URL. If you generate a new PKCE pair, the authorization code will be rejected.

## Features

- Obtain Tesla API access tokens and refresh tokens
- Uses Tesla's current OAuth 2.0 Authorization Code flow with PKCE
- Built with Java 17 and Maven
- Includes proper error handling and exception management
- Supports token refresh functionality

## Prerequisites

- Java 17 or higher
- Maven 3.6 or higher
- Tesla account
- Web browser for OAuth authorization

## Installation

1. Clone the repository:
```bash
git clone https://github.com/vladimirgumenny/tesla-auth-service.git
cd tesla-auth-service
```

2. Build the project:
```bash
mvn clean compile
```

## Usage

### OAuth 2.0 Flow Overview

The new authentication flow works as follows:

1. **Generate Authorization URL**: Create a URL for the user to visit in their browser
2. **User Authorization**: User visits the URL and authorizes your application
3. **Immediate Code Exchange**: **CRITICAL**: Exchange the authorization code for tokens using the SAME PKCE code verifier
4. **Token Refresh**: Use refresh tokens to get new access tokens when they expire

### Complete Working Example

```java
import org.example.tesla.auth.TeslaTokenService;

public class WorkingExample {
    public static void main(String[] args) {
        TeslaTokenService service = new TeslaTokenService();
        
        try {
            // Step 1: Generate authorization URL and store the result
            TeslaTokenService.AuthorizationResult authResult = service.getAuthorizationUrl();
            String authUrl = authResult.getAuthorizationUrl();
            String state = authResult.getState();
            
            System.out.println("Visit this URL to authorize: " + authUrl);
            System.out.println("State parameter: " + state);
            
            // Step 2: User visits the URL and authorizes
            // After authorization, user gets redirected with an authorization code
            
            // Step 3: IMMEDIATELY exchange the code using the stored state
            // The authorization code is only valid for a few minutes
            String authCode = "authorization_code_from_browser";
            TeslaTokenService.Tokens tokens = service.exchangeCodeForTokensWithState(authCode, state);
            
            System.out.println("Access Token: " + tokens.getAccessToken());
            System.out.println("Refresh Token: " + tokens.getRefreshToken());
            
            // Step 4: Refresh tokens when they expire
            TeslaTokenService.Tokens newTokens = service.refreshTokens(tokens.getRefreshToken());
            
        } catch (TeslaTokenService.TeslaTokenServiceException e) {
            System.err.println("Authentication failed: " + e.getMessage());
        }
    }
}
```

### What NOT to Do

❌ **Don't generate a new authorization URL after getting the authorization code**
❌ **Don't wait too long to exchange the authorization code (it expires quickly)**
❌ **Don't lose the state parameter - you need it to retrieve the stored PKCE**

### What TO Do

✅ **Generate the authorization URL once and store the result**
✅ **Use the authorization code immediately with the same state parameter**
✅ **Keep the state parameter until you've exchanged the code for tokens**

## API Reference

### TeslaTokenService

Main service class for Tesla authentication.

#### Constructor
- `TeslaTokenService()` - Creates a service with default HttpClient and ObjectMapper
- `TeslaTokenService(HttpClient httpClient, ObjectMapper objectMapper)` - Creates a service with custom dependencies

#### Methods
- `getAuthorizationUrl()` - Generates the OAuth authorization URL for user to visit. **Returns AuthorizationResult with URL and state**
- `exchangeCodeForTokensWithState(String authCode, String state)` - Exchanges authorization code for tokens using stored PKCE
- `exchangeCodeForTokens(String authCode, String codeVerifier)` - Exchanges authorization code for tokens with explicit code verifier
- `refreshTokens(String refreshToken)` - Refreshes access token using refresh token

### AuthorizationResult

Data class containing the authorization URL and state parameter.

#### Fields
- `authorizationUrl` - The URL for the user to visit
- `state` - The state parameter that must be used with the authorization code

### PKCEPair

Data class containing PKCE (Proof Key for Code Exchange) values.

#### Fields
- `codeVerifier` - The code verifier for PKCE
- `codeChallenge` - The code challenge derived from the verifier

### Tokens

Data class containing the authentication tokens.

#### Fields
- `accessToken` - The access token for API calls
- `refreshToken` - The refresh token for obtaining new access tokens
- `tokenType` - The type of token (usually "Bearer")
- `expiresInSeconds` - Token expiration time in seconds
- `createdAtEpochSeconds` - Token creation timestamp

### TeslaTokenServiceException

Exception thrown when authentication fails.

## Security Considerations

⚠️ **Important Security Notes:**

1. **PKCE Implementation**: This service implements PKCE (Proof Key for Code Exchange) for enhanced security:
   - Code verifier must be stored securely and associated with the authorization request
   - Code challenge is sent with the authorization request
   - Code verifier is required when exchanging the authorization code for tokens
   - **CRITICAL**: Authorization codes are bound to their specific PKCE code verifier

2. **State Parameter**: The service generates a random state parameter for CSRF protection.

3. **Token Storage**: Store tokens securely and never expose them in logs or error messages.

4. **OAuth Flow**: This is a proper OAuth 2.0 implementation that follows security best practices.

5. **No Credential Handling**: Unlike the deprecated password flow, this service never handles user credentials directly.

6. **Authorization Code Expiry**: Authorization codes expire quickly (usually within 10 minutes), so exchange them immediately.

## Implementation Notes

### For Web Applications
- Store PKCE code verifier in session or secure storage
- Handle the OAuth callback properly
- Validate the state parameter
- Implement proper error handling
- Exchange the authorization code immediately upon receipt

### For Mobile Applications
- Use custom URL schemes for OAuth callbacks
- Store PKCE code verifier securely
- Handle deep linking for OAuth completion
- Exchange the authorization code immediately upon receipt

### For Desktop Applications
- Use localhost redirect URIs
- Implement local server for OAuth callback handling
- Store PKCE code verifier in secure local storage
- Exchange the authorization code immediately upon receipt

## Troubleshooting

### Common Errors

1. **"Invalid code_verifier"**: You're using a different PKCE code verifier than the one used to generate the authorization URL. Use the same state parameter.

2. **"Authorization code expired"**: Authorization codes expire quickly. Exchange them immediately after receipt.

3. **"Invalid state parameter"**: The state parameter doesn't match any stored PKCE. Generate a new authorization URL.

## Dependencies

- Java 17+
- Jackson (for JSON processing)
- Maven (for build management)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This project is not affiliated with Tesla, Inc. Use at your own risk and in compliance with Tesla's Terms of Service and API usage policies.
