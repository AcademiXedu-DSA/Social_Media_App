# Social_Media_App
->AuthController
->User
->UserRepository
->JwtRequestFilter
->JwtUtil
->SecurityConfig
->AuthService
->SessionManager

# AuthController
 ----------------------------- LOGIN ----------------
>Extracts the username and password from the request.
>Calls AuthService.authenticate() to check if the credentials are valid.
>If valid, it generates a JWT token using AuthService.generateToken() and sends it back to the client.
>If invalid, it returns a 401 Unauthorized response.
-------------------------------Register------------------------
>Give user details (e.g., username, password, email) from the request.
>Checks if the username already exists in the UserRepository.
>If the user exists, it returns an error response.
>If the user doesn't exist, it hashes the password, creates a new User object, and saves it to the database.
>Returns a success response after saving the user.
--------------------------Logout-----------------------------------
>Get the JWT token from the request's Authorization header.
>Check if the token is valid using sessionManager.
>If the token is valid:
>Remove it from the active sessions to log the user out.
>Return a success message (200 OK).
>If the token is invalid or expired:
>Return an error message (400 Bad Request).
# user

>The User class represents a user entity in the system. It maps to a database table and holds fields related to user information.
>id: Unique identifier for each user.
>username: Username chosen by the user, used for login.
>password: User’s password, typically stored in a hashed format.
>Other fields: Such as roles for managing access levels, email, etc.
# UserRepository

>UserRepository is a data access layer interface that extends JpaRepository
>It provides methods to interact with the User entity in the database, allowing for CRUD operations.
ex : findByUsername(String username): Fetches a user based on their username, which is often used during authentication.

# JwtRequestFilter

>Get the Authorization header from the incoming request.
>Check if the header exists and starts with "token ".
>If not, skip token validation and continue to the next filter.
>Use JwtUtil to extract the username from the token.
  Check if:
        The username is not null, and
        The user is not already authenticated in the SecurityContext.
>If both conditions are true:
>Load user details from the database using UserDetailsService.
>Validate the token with JwtUtil and the loaded user details.
>If the token is valid:
    Create an authentication object with the user’s details.
    Set this authentication object in the SecurityContext.
>Proceed with the request by calling filterChain.doFilter().
# JwtUtil.java
1. Jwtutil is to manage creation ,validation,extraction of json web tokens
2. It contains a security key that is used by the server to sign and verify the JWT token.
3. It contains methods like
generateToken-used to generate JWT token after succesfull login of user This token can then be sent to the client, who stores it (e.g., in local storage or cookies) for use in future requests.
isTokenValid-Every time a client make request to a protected endpoint, the client sends the JWT along with the request.
4. JwtUtil verifies the token to ensure it hasn’t been tampered with, and it checks if the token is still valid (i.e., hasn’t expired).

# SecurityConfig

Set up UserDetailsService to manage user information and use a password encoder (e.g., BCrypt) for secure password handling.

Disable CSRF if not needed.

Allow open access to public endpoints (e.g., /auth/login and /auth/register).

Require authentication for all other endpoints.

Add JwtRequestFilter before the main authentication filter to process JWTs.

Provide a passwordEncoder (e.g., BCrypt) and expose authenticationManager for handling custom authentication with JWTs.

# AuthService

register(username, password):

Checks if the username is already taken.
Encodes the password and saves the new user in the database.
login(username, password):

Finds the user in the database.
Verifies the password.
Generates a JWT token and stores it as an active session.
Returns the JWT token.
logout(token):

Checks if the token is valid.
Removes the token from active sessions if valid, invalidating the session.

# SessionManager

We use SessionManager class to store user sessions. This will usually be a HashMap where the key is the JWT token , and the value is the username.
It contains methods like
1. *createSession*
Purpose:
Creates a new session for an authenticated user, generates a session token, and stores it along with session metadata.
Function: 
Store session with user ID and expiration time

2. *invalidateSession*
Purpose:
Invalidates an active session by removing the session token from storage, logging the user out.
Function: 
Check if session token exists in storage if sessiontoken in sessions then it Remove the session token to invalidate the session delete sessions

3. *isSessionValid*
Purpose:
Checks if a given session token is valid by confirming its existence and expiration status.
Function: 
 Check if session token exists in sessions. Check if session has expire if sessions is expired then it return true
 if session is invalid return False