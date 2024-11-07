# JWT-Based Authentication with Spring Security

This project implements a simple login and logout API using Spring Security, JWT (JSON Web Token), and session storage. It demonstrates how to secure a Spring Boot application by storing JWT tokens in the session upon login and removing them on logout.

## Project Overview

This application allows users to:
- Log in using a username and password to receive a JWT token stored in the session.
- Log out by removing the JWT token from the session, effectively invalidating the session.

### Key Technologies
- **Spring Boot**: Simplified application setup and configuration.
- **Spring Security**: Provides robust authentication and authorization mechanisms.
- **JWT**: Used to generate and validate tokens.
- **Session Management**: Stores the JWT token server-side upon login.
- **MapStruct**: Maps between entities and DTOs.

## Components

### Entity: `User`
- Represents a user record in the database with fields like `id`, `username`, `password`, and `role`.
- **Password Storage**: Always store passwords as hashes (e.g., BCrypt) for security.

### Repository: `UserRepository`
- Interfaces with the database to retrieve user information.
- Contains methods for finding users by username, crucial for the login process.

### DTOs (Data Transfer Objects)
- **LoginRequestDTO**: Represents the incoming login request with `username` and `password`.
- **LoginResponseDTO**: Represents the successful login response, containing the JWT token and a success message.
- **LogoutResponseDTO**: Represents a successful logout response, containing a success message.

### Mapper: `UserMapper`
- Uses MapStruct to convert between `User` entities and DTOs.
- Simplifies the transformation of data between different application layers.

### Service: `AuthService`
- Contains business logic for login and logout processes.
    - **Login**: Validates user credentials, generates a JWT token upon successful authentication, and stores it in the session.
    - **Logout**: Removes the JWT token from the session.
- Includes helper methods for hashing and validating passwords.

### Controller: `AuthController`
- Exposes REST endpoints for login and logout.
    - **POST /auth/login**: Accepts `LoginRequestDTO`, calls `AuthService` to authenticate the user, and returns `LoginResponseDTO`.
    - **POST /auth/logout**: Removes the JWT token from the session and returns `LogoutResponseDTO`.

### JWT Utility: `JwtUtil`
- Manages JWT generation, validation, and extraction.
    - **Generate Token**: Generates a JWT token using user details.
    - **Validate Token**: Validates the token’s authenticity.
    - **Extract Username**: Retrieves the username from the JWT, aiding in user identification.

### Spring Security Configuration: `SecurityConfig`
- Configures Spring Security settings for authentication and session management.
    - **Session Management**: Creates a session for each authenticated user.
    - **Public Access**: Allows unauthenticated access to login and logout endpoints.
    - **Protected Endpoints**: Restricts access to other application endpoints.

## Flow Overview

### Login Process
1. **Client Request**: The client sends a POST request with login credentials to `/auth/login`.
2. **AuthService Login Logic**:
    - Authenticates the credentials.
    - Generates a JWT token if authentication is successful.
    - Stores the JWT token in the HTTP session.
3. **Response**: Returns `LoginResponseDTO` with the JWT token and success message.

### Logout Process
1. **Client Request**: The client sends a POST request to `/auth/logout`.
2. **AuthService Logout Logic**:
    - Clears the JWT token from the HTTP session.
3. **Response**: Returns `LogoutResponseDTO` confirming the logout.

## Security Configuration

### Spring Security Setup
- **Session Management**: Configures sessions to store JWT tokens.
- **Public Access**: Grants unauthenticated access to `/auth/login` and `/auth/logout`.
- **Protected Endpoints**: Other endpoints require authentication.

### Token Management
- **Session Storage**: Stores JWT tokens in the session to simplify authentication and session tracking.
- **Token Validation**: API requests check for the session-stored token to ensure authentication status.

## Prerequisites
1. **MapStruct**: Include MapStruct dependencies for DTO mapping.
2. **JWT Library**: Include a JWT library (e.g., `io.jsonwebtoken`) to handle token operations.
3. **Password Encryption**: Use a hashing algorithm like BCrypt for password security.

## Additional Notes
- **Password Hashing**: Ensure passwords are stored as hashed values.
- **Token Expiration**: Set token expiration for added security.
- **Session-Based Management**: For applications needing stateless authentication, consider client-side token storage instead of sessions.
