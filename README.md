# Social_Media_App
// *Setting up the Database*
1. Add H2 database dependency in pom.xml
    - <dependency>
        - groupId: 'com.h2database'
        - artifactId: 'h2'
        - version: '2.1.214' (use the latest version)
      </dependency>

2. Configure H2 database in application.properties
    - Set spring.datasource.url to 'jdbc:h2:mem:testdb' (In-memory database for testing)
    - Set spring.datasource.driverClassName to 'org.h2.Driver'
    - Set spring.datasource.username to 'sa'
    - Set spring.datasource.password to ''
    - Set spring.jpa.hibernate.ddl-auto to 'update'
    - Optionally, enable the H2 console: spring.h2.console.enabled=true

3. Create User table in the database using the User entity
    - User.java defines:
        - username (String): Should be unique, annotation: @Column(unique = true)
        - password (String): Hashed password (using Bcrypt)
        - role (String): Defines the role (e.g., "USER", "ADMIN")
    - Add JPA annotations (@Entity, @Id, @GeneratedValue) for User entity

// *USER REGISTRATION*
1. Create a /register endpoint in AuthController
    - Method: registerUser(@RequestBody User user)
        - Check if user already exists in the database:
            - If user exists: Return "USER ALREADY EXISTS! PLEASE LOGIN"
        - If user doesn't exist:
            - Encrypt the user's plain password using Bcrypt password encoder
            - Store the hashed password, username, and role in the database
            - Return "USER REGISTERED SUCCESSFULLY"

// *USER LOGIN*
1. Create a /login endpoint in AuthController
    - Method: loginUser(@RequestParam String username, @RequestParam String password)
        - Call AuthService.authenticateUser(username, password)
            - In authenticateUser:
                - Fetch the user by username from UserRepository
                - Compare the hashed password stored in the database with the plain password (hashed) entered by the user using Bcrypt
                - If passwords match: Return "USER LOGIN SUCCESSFULLY"
                - If passwords don't match: Return "INVALID CREDENTIALS"
            
2. Generate JWT token upon successful login:
    - Use JwtUtil.java to generate a JWT token (HS256 algorithm)
    - Include user-specific information (username, role) in the JWT payload

3. Store the JWT token and username in SessionManager (using HashMap)
    - Method: storeSession(username, jwtToken) in SessionManager

// *USER LOGOUT*
1. Create a /logout endpoint in AuthController
    - Method: logoutUser(@RequestParam String username)
        - Call AuthService.logout(username)
            - In logout:
                - Check if session exists in SessionManager using the username
                - If session exists:
                    - Remove the session from SessionManager
                    - Return "USER LOGGED OUT SUCCESSFULLY"
                - If no session found: Return "NO ACTIVE SESSION FOUND"

// *Security Config*
1. Create WebSecurityConfig class to protect URLs
    - Public URLs:
        - Allow access to /register and /login without authentication
    - Private URLs:
        - Protect /profile, /dashboard, and other sensitive endpoints
        - Only authenticated users should be able to access private URLs

2. Configure HttpSecurity to set public and private endpoints
    - Allow unrestricted access to /register and /login
    - Protect other endpoints (e.g., /profile, /dashboard)
        - Require authentication (use JWT token) for access to these routes

3. Create JwtRequestFilter class to validate JWT tokens
    - In JwtRequestFilter:
        - Intercept every incoming request
        - Extract and validate the JWT token from request headers
        - If token is valid and not expired:
            - Allow access to private endpoints
        - If token is invalid or expired:
            - Return an unauthorized error (401)

4. Apply JwtRequestFilter to intercept requests
    - Add JwtRequestFilter to Spring Security filter chain to validate the JWT before allowing access to protected routes

// *Example Flow for Securing Access*
1. A user logs in and receives a JWT token.
2. User tries to access a private endpoint (/dashboard):
    - The request contains the JWT token in the Authorization header.
    - The JwtRequestFilter validates the JWT token:
        - If the token is valid, the user is allowed access to the /dashboard.
        - If the token is invalid, the user receives an unauthorized error (401).
3. The user can log out, which removes the session from the SessionManager, preventing further access.