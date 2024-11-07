overview:

AuthController.java
This file defines the endpoints for user registration, login, and logout, providing a REST API interface for user actions.

AuthService.java
This file handles the business logic of user registration, login, and logout, interacting with UserRepository, SessionManager, and JwtUtil to manage users and sessions securely.

SessionManager.java
Manages sessions by storing active JWT tokens associated with usernames. It ensures that each user has only one active session at a time.

User.java
Represents the user entity in the database, with fields for id, username, and password. This entity maps directly to a users table in the database.

UserRepository.java
Defines a repository interface to access User data from the database, providing methods to retrieve users by username and save new users.

JwtRequestFilter.java
Filters incoming HTTP requests, checking for a valid JWT token and setting the authentication if valid. Works with SessionManager and JwtUtil to validate sessions.

JwtUtil.java
Utility class for creating, parsing, and validating JWT tokens. Manages the extraction of user information and token expiration.

SecurityConfig.java
Configures Spring Security, defining access rules for endpoints, disabling CSRF and CORS, and adding JWT-based authentication for secure access

USER REGISTRATION:
1.User hits the registration endpoint (/auth/register) by sending a request with username and password.
2.Checks if the user already exists by querying the database. If the user exists, it returns an error; otherwise, proceeds with registration.
3.Hashes the password using BCrypt for security and then saves the user details.
4.Saves the registration details in the database using UserRepository.
5.Returns a success message upon successful registration: "User registered successfully".

USER LOGIN:
1.User logs in by hitting the login endpoint (/auth/login) with username and password.
2.Validates the password by comparing it with the stored hashed password using BCrypt.
3.If valid, proceeds; otherwise, returns an error.
4.Generates a JWT token upon successful validation using JwtUtil.
5.Stores the JWT token in SessionManager for session management.
6.SessionManager stores tokens and usernames in a HashMap, ensuring each user has one active session.
7.Returns the token if successful. If the user does not exist, returns "User Not Found".

USER LOGOUT:
1.User hits the logout endpoint (/auth/logout).
2.Retrieves the Authorization header, which holds the user’s credentials.
3.Checks if the session exists in SessionManager using either the username or JWT token.
4.Validates the Authorization header to ensure it’s a valid JWT .
5.Extracts the username from the token using JwtUtil.
6.Calls the logout method in AuthService, passing the username to remove the session.
7.Deletes the token from the session and returns "Logged out successfully" if the process is successful.

JWT PROCESSING WITH JWT REQUEST FLITER AND JWT UTIL: 
JWT REQUEST FILTER:
1.Extracts the Authorization header from each incoming HTTP request.
2.Validates the Authorization header format, ensuring it starts with "Bearer ".
3.Extracts the JWT token from the Authorization header.
4.Uses JwtUtil to extract the username from the token.
5.Checks the validity of the session using SessionManager to confirm the user has an active session.
6.If the session is valid, creates a UserDetails object for the username.
7.Validates the JWT token by checking its signature and expiration status with JwtUtil.
Sets the authentication in SecurityContext if the JWT is valid, allowing access to protected endpoints.
8.Passes the request and response to the next filter in the security chain.

JWT UTIL:
1.Extracts the username from a JWT token by decoding it.
2.Retrieves the token’s expiration date to check if the token is still valid.
3.Extracts specific claims (like username or expiration) by decoding with a SECRET_KEY.
4.Retrieves all claims from a token for full validation.
5.Checks token expiration to determine if it’s valid for further processing.
6.Generates a new token with user-specific claims (like username) and a secure signature.
7.Creates and signs tokens based on user data and security algorithms.
Validates tokens for authenticity, ensuring the token has not expired or been tampered with.

SECURITY CONFIG:
1.Disables CSRF for the application to prevent CSRF attacks.
2.Enables CORS configuration to allow requests from trusted domains.
3.Sets session management to stateless for JWT-based authentication, ensuring no sessions are kept.
4.Allows unauthenticated access to /auth/register, /auth/login, and /h2-console/ for registration and development.
5.Requires authentication for all other endpoints.
6.Adds JwtRequestFilter before the UsernamePasswordAuthenticationFilter for JWT verification.
7.Allows access to the H2 console in development mode.
8.Configures password encoding with BCrypt for user password hashing.
9.Allows CORS from http://localhost:3000, enabling specific HTTP methods and headers, with credential support for frontend development.

Dependencies used:

Spring Boot Starter Web: Provides the core libraries to build web applications .
Spring Boot Starter Security: Adds security features like authentication, authorization, and password encoding.
Spring Boot Starter Data JPA:  Interacts with databases.
jjwt: Java JWT (JSON Web Token) library for creating and validating JWT tokens.
BCrypt: For hashing passwords securely.
H2 Database: An in-memory database for development and testing, configured with Spring Boot.
 