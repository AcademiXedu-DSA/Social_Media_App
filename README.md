**Sign-up (register):**

Receive user information.
Register the user using **AuthService**.
Generate a JWT token using **JwtUtil**.
Create a session for the user with **SessionManager**.
Return a response containing the username, token, and a success message.
Handle exceptions by returning an error message.

**Sign-in (login):**

Check if credentials are valid (username and password).
Authenticate the user with **AuthService**.
If valid, generate a JWT token and create a session.
Return a response containing the username and token.
Handle invalid credentials or authentication failure by returning an error.

Sign-out (logout):

Extract the token from the request header.
Validate the token and extract the username using **JwtUtil**.
Check if the session is valid, and if so, log out the user.
Invalidate the session using **SessionManager**.
Return a success or error message.

JWT Filter Logic:

Extract JWT token from the request header.
If token exists, extract username using **JwtUtil**.
Check session validity with **SessionManager**.
Validate token and set user authentication.
Continue filter chain.

JWTutil Methods:

Extract username and expiration from token.
Generate a new JWT token for a user.
Validate a token against a user.
Check if a token is expired.

AuthService Methods:

Register:
Check if username exists, encode password, and save user.
Authenticate:
Validate user credentials (username and password).
Logout:
Invalidate the user's session.


SessionManager Methods:

createSession: Store a new session (username-token pair).
invalidateSession: Remove the user's session.
isSessionValid: Check if a session is valid based on username and token.
clearAllSessions: Remove all sessions.
getTokenForUser: Get the token for a specific user.

Security Config:

Disable CSRF, configure CORS.
Permit all requests to /api/auth/** and /h2-console/**.
Require authentication for all other endpoints.
