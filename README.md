# Tesla Authentication Service

A Java service for obtaining Tesla API access tokens and refresh tokens using username and password authentication.
<p>
Note: 
    Authentication failed: Token request failed: HTTP 400: {"response":null,"error":"Endpoint deprecated: Please update your App.","error_description":""}

## Features

- Obtain Tesla API access tokens and refresh tokens
- Uses Tesla's OAuth 2.0 password grant flow
- Built with Java 17 and Maven
- Includes proper error handling and exception management

## Prerequisites

- Java 17 or higher
- Maven 3.6 or higher
- Tesla account credentials

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

### Basic Usage

```java
import org.example.tesla.auth.TeslaTokenService;

public class Example {
    public static void main(String[] args) {
        TeslaTokenService service = new TeslaTokenService();
        
        try {
            TeslaTokenService.Tokens tokens = service.fetchTokensWithPasswordGrant(
                "your-email@example.com", 
                "your-password"
            );
            
            System.out.println("Access Token: " + tokens.getAccessToken());
            System.out.println("Refresh Token: " + tokens.getRefreshToken());
            System.out.println("Token Type: " + tokens.getTokenType());
            System.out.println("Expires In: " + tokens.getExpiresInSeconds() + " seconds");
            
        } catch (TeslaTokenService.TeslaTokenServiceException e) {
            System.err.println("Authentication failed: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
        }
    }
}
```

### Advanced Usage with Custom HttpClient

```java
import org.example.tesla.auth.TeslaTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import java.time.Duration;

public class AdvancedExample {
    public static void main(String[] args) {
        HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();
            
        ObjectMapper objectMapper = new ObjectMapper();
        TeslaTokenService service = new TeslaTokenService(httpClient, objectMapper);
        
        // Use the service as before...
    }
}
```

## API Reference

### TeslaTokenService

Main service class for Tesla authentication.

#### Constructor
- `TeslaTokenService()` - Creates a service with default HttpClient and ObjectMapper
- `TeslaTokenService(HttpClient httpClient, ObjectMapper objectMapper)` - Creates a service with custom dependencies

#### Methods
- `fetchTokensWithPasswordGrant(String email, String password)` - Obtains tokens using email and password

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

1. **Credential Handling**: This service handles user credentials directly. Ensure proper security measures are in place:
   - Never log or store credentials
   - Use secure communication channels
   - Implement proper access controls

2. **MFA Limitations**: This flow may not work for accounts with Multi-Factor Authentication (MFA) enabled.

3. **Token Storage**: Store tokens securely and never expose them in logs or error messages.

4. **Production Use**: For production applications, consider using Tesla's OAuth 2.0 Authorization Code flow with PKCE instead of password grant.

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
