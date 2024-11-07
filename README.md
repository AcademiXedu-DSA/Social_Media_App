# Social_Media_App


## Project Dependencies

The following dependencies are required for the project:
- **Spring Security**: Provides security configuration and session management.
- **BCrypt**: Used for hashing passwords.
- **JWT (JSON Web Token)**: Used for generating, validating, and managing tokens.
- **JPA (Java Persistence API)**: For interacting with the H2 database.
- **Lombok**: Reduces boilerplate code with annotations.
- **H2 Database**: An in-memory database for development and testing.
- **Spring Web**: For building web applications.
- **Validation**: To validate user input during registration and login.

## Pseudo code

### 1. User Registration and Login(**operations**):

- **Register**: 
    - Users submit their username and password.
    - The password is validated and hashed using BCrypt before storing in the database.
    - User data is saved in the H2 database with hashed passwords.

- **Login**:
    - Users submit their username and password.
    - The system validates the credentials against the stored data.
    - If valid, a JWT token is generated and provided to the user for session management.
 
### 2.Creating a Entity:(**Structure**):
    -Username(validation)(regex)(NotNull)
    -pass(NotNull)

### 3. Updating the Database(**Service**)
    - Becrypting the password.
    - Entering the User name and hashed pass to the H2 Db.
    #Login
    -Verifying the hashedpass and user
    -sending the sessionid and managing it.


### 4. Session Management

- **RegisterSession**:
    - Manages active sessions by associating users with tokens.
    - Handles session expiration to ensure that tokens have a limited lifetime.

- **Session Management**:
    - Verifies active sessions.
    - Checks if the session has expired.
    - Updates or removes sessions as needed.

### 5. JWT Token Management

- **JWTRequestFilter**:
    - Intercepts requests to validate the JWT token for authorization.
    - If the token is not valid, access to protected resources is denied.

- **JWTUtil**:
    - Generates JWT tokens using user details.
    - Validates tokens upon each request to a protected page.
    - Manages token expiration(giving the expire of the session).

### 6. Security Configuration

- **SecurityConfig**:
    - Configures which URLs are protected and require a valid session.
    - Integrates with JWTUtil to ensure only authenticated users can access protected endpoints.

### Database

- **H2 Database**:
    - Configuring the H2
    - Server port

## Protected Pages

 ## Logout:
    - Session manage to remove the session.

## Controller :

- **POST /register**: Registers a new user.
- **POST /login**: Authenticates a user and returns a JWT token.
- **GET /protected**: A protected endpoint accessible only to authenticated users with a valid token.
- **POST /logout**: Ends the user's session and invalidates the JWT token.

