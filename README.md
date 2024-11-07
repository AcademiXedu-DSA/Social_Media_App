# Social_Media_App
1. Register Endpoint (/register)
Flow:Client -> AuthController -> AuthService -> UserRepository -> Response
1.Client Request:
The client sends a POST request to /register with user details like username, password, and role.
2.Controller (AuthController):
Calls register() to handle the registration.
Passes the user data to AuthService.registerUser() for processing.
3.Service (AuthService):
Check Username: Uses UserRepository to see if the username is already taken.
Encrypt Password: If the username is available, encrypts the password for secure storage.
Save User: Creates and saves a new user record in the database using UserRepository.
4.Response:
Sends a success message back to the client if registration is successful.
5.Components Involved:
Controller: AuthController
Service: AuthService
Repository: UserRepository
Model: User


2. **Login Endpoint (/authenticate)**
Flow:Client -> AuthController -> AuthService -> UserRepository -> JwtUtil -> Response
1.Client Request:
The client sends a POST request to /authenticate with username and password.
2.Controller (AuthController):
Calls login() to process the login request.
Passes the credentials to AuthService.authenticateUser().
3.Service (AuthService):
Load User: Retrieves the user’s information using UserRepository.
Validate Password: Compares the entered password with the stored encrypted password.
Generate JWT: If credentials are correct, generates a JWT using JwtUtil to allow secure access.
4.Response:
Sends the JWT back to the client to use for future requests.
5.Components Involved:
Controller: AuthController
Service: AuthService
Repository: UserRepository
Model: User
Security: JwtUtil


3. **Logout Endpoint (/logout) (Optional)**
Flow:Client -> AuthController -> SessionManager -> Response
1.Client Request:
The client sends a POST request to /logout, optionally including the JWT (or handles logout locally by removing the token).
2.Controller (AuthController):
Calls logout() to handle the request.
Passes the token to SessionManager.invalidateToken().
3.Session Management (SessionManager):
Invalidate Token: Removes the token from a valid list or adds it to a blacklist to prevent further use.
4.Response:
Sends a success message indicating that logout was successful.
5.Components Involved:
Controller: AuthController
Service: SessionManager (for token management if implemented)


4. **JWT Token Validation (for Secured Endpoints)**
Flow:Client -> JwtRequestFilter -> JwtUtil -> SecurityContext -> Controller
1.Client Request:
The client sends a request to a secured endpoint (e.g., /user, /availability), including the JWT in the Authorization header.
2.Filter (JwtRequestFilter):
Extract JWT: Reads the token from the header.
Validate Token: Calls JwtUtil to check if the token is valid and unexpired.
Set Authentication: If the token is valid, sets the user’s authentication context, allowing access to the endpoint.
3.Controller Access:
If the token is valid, the request is allowed to reach the intended controller.
4.Components Involved:
Security: JwtRequestFilter, JwtUtil
Config: SecurityConfig (to set up filter chain and session management)

**THE FILES THAT WE ARE USED EXPLAINED IN DETAILED MANNER**

1. **AuthController**
Functionality:
The AuthController handles incoming HTTP requests related to user authentication and registration. It provides endpoints for:
- Register: Accepts user registration data, such as username and password, and sends this data to AuthService for processing.
- Login: Accepts login credentials (username and password) and, if valid, issues a JWT token to the user.
- Logout: Optionally invalidates a user's session or token, handled by SessionManager.

2.**User**
Functionality:
User is a model class representing the user entity in the database. It typically includes:
- Fields: Attributes like id, username, password, and role (e.g., USER or ADMIN).
- Annotations: JPA or MongoDB annotations to map the class to the database table or collection.
- Getters and Setters: Used to access and modify fields, either via Lombok annotations or explicitly written methods.
This model defines the structure of user data stored in the database.

3. **UserRepository**
Functionality:
UserRepository is an interface that provides CRUD operations on User entities. It typically extends MongoRepository or JpaRepository and includes:
findByUsername(String username): A method to find users by their username, useful for login and token validation.
Additional Methods: Define additional methods for querying users if needed.

4. **JwtRequestFilter**
Functionality:
The JwtRequestFilter intercepts incoming HTTP requests and verifies if they contain a valid JWT token in the Authorization header. It performs:
- Token Extraction: Retrieves the JWT from the header.
- Token Validation: Uses JwtUtil to check if the token is valid.
- Set Authentication: If the token is valid, retrieves user details and sets the authentication context to authorize access to protected resources.

5. **JwtUtil**
Functionality:
JwtUtil handles operations related to JSON Web Tokens (JWTs). It includes methods to:
- Generate Tokens: Creates a JWT based on user details, which will be sent to the client after successful login.
- Validate Tokens: Checks if the token is valid (correct signature and unexpired).
- Extract User Information: Retrieves claims (e.g., username, roles) from the token for use in authentication.

6.**SecurityConfig**
Functionality:
The SecurityConfig class is the main configuration for Spring Security, setting up:
- Authentication Manager: Specifies how authentication is managed, linking to a UserDetailsService that loads user details.
- JWT Filter: Registers JwtRequestFilter to run for each request.
- Endpoint Protection: Specifies which endpoints require authentication and which are publicly accessible.
- Password Encoding: Configures a password encoder (e.g., BCryptPasswordEncoder) to securely store passwords.

7. **AuthService**
Functionality:
AuthService contains the core authentication logic, including methods for:
- Register: Checks if the username exists, encrypts the password, and saves the user.
- Login: Validates the user’s credentials and generates a JWT if they are correct.
- Role Assignment: Manages role assignment for the user during registration or account updates.

8. **SessionManager**
Functionality:
SessionManager is responsible for managing user sessions. It performs tasks such as:
- Token Blacklisting: Optionally stores tokens in a blacklist or removes them to invalidate sessions.
- Session Validation: Ensures that user sessions are active and the JWT is not blacklisted.
- This is optional but can enhance security for logout and token revocation