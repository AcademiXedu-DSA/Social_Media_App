# Authentication System Pseudocode

## User sign-up

1. **Check if Username Exists**
    - Query the database for the provided username.
    - If the username already exists, throw an error: "Username already taken."

2. **Encrypt Password**
    - Use `passwordEncoder` to hash the user's password.

3. **Save User**
    - Save the new user to the database using `userRepository`.

4. **Generate JWT**
    - Generate a JWT for the user using `jwtUtil`.

5. **Create Session**
    - Create a session in `sessionManager`, associating the username with the JWT token.

6. **Return Success Response**
    - Respond with a JSON object containing:
        - `token`: The generated JWT.
        - `username`: The registered username.

---

## User sign-in

1. **Check Request for Credentials**
    - Ensure the login request contains both `username` and `password`.
    - If not, return an error response: "Username and password required."

2. **Authenticate User**
    - Call `authService.authenticate` to validate credentials.
    
3. **Retrieve User**
    - Query the database for the user using `userRepository`.

4. **Compare Password**
    - Use `passwordEncoder` to compare the provided password with the stored password.

5. **Successful Authentication**
    - If authentication succeeds:
        - Generate a JWT using `jwtUtil`.
        - Create a session for the user in `sessionManager`.

6. **Return Success Response**
    - Respond with a JSON object containing:
        - `token`: The generated JWT.
        - `username`: The authenticated username.

7. **Failed Authentication**
    - If authentication fails, return an error message: "Invalid credentials."

---

## User sign-out

1. **Check Authorization Header**
    - Ensure the logout request contains a valid Bearer token in the `Authorization` header.
    - If not, return an error response: "Missing or invalid token."

2. **Extract JWT**
    - Extract the JWT token from the Bearer header.

3. **Extract Username from JWT**
    - Use `jwtUtil` to extract the username from the token.

4. **Validate Token**
    - Validate the token using `jwtUtil` to check for expiration or tampering.
    - Ensure the username in the token matches the extracted username.

5. **Token Validity**
    - If the token is valid:
        - Invalidate the session using `sessionManager.invalidateSession`.

6. **Return Success Message**
    - Respond with a message: "Logout successful."

7. **Invalid Token**
    - If the token is invalid or expired, return an error message: "Invalid or expired token."

---

## JWTutil Methods

- **Extract Username from Token**: Decode the JWT to extract the username.
- **Generate Token**: Create a new JWT token for a given user.
- **Validate Token**: Check if the provided token is valid.
- **Check Expiration**: Ensure the token has not expired.

---

## AuthService Methods

- **Register**:
    - Check if the username exists in the database.
    - Encode the user's password.
    - Save the user details to the database.
    
- **Authenticate**:
    - Validate the username and password provided by the user.

- **Logout**:
    - Invalidate the session for the user.

---

## SessionManager Methods

- **createSession**: Store a session (username-token pair).
- **invalidateSession**: Remove the user's session based on the username.
- **isSessionValid**: Verify if the session is valid for the username and token.
- **clearAllSessions**: Remove all active sessions.
- **getTokenForUser**: Retrieve the token associated with a specific user.

---

## Security Config

- **CSRF and CORS**:
    - Disable CSRF protection.
    - Configure CORS for frontend requests.

- **Permitted Endpoints**:
    - Allow access to `/api/auth/**` and `/h2-console/**` without authentication.

- **Authentication**:
    - Require JWT-based authentication for all other endpoints.

