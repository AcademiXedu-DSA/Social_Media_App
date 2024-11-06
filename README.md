# Social_Media_App
// Main Application - UserAuthApplication.java
START class UserAuthApplication
    METHOD main(String[] args)
        Initialize Spring Boot application context
        Load all configurations and beans
END class

// Configuration - application.properties
# Database Configuration
Set spring.datasource.url to your database URL
Set spring.datasource.username to your database username
Set spring.datasource.password to your database password

# Server and Security
Set server.port to desired port number
Optionally enable H2 console (spring.h2.console.enabled=true) if using H2 database

// Security Configuration - WebSecurityConfig.java
START class WebSecurityConfig
    @Bean PasswordEncoder -> Configure BCryptPasswordEncoder for password hashing
    
    METHOD configure(HttpSecurity http)
        Set endpoint access rules (e.g., allow /register, secure others)
        Configure login and logout settings
        Enable CSRF protection if needed
        
    METHOD configure(AuthenticationManagerBuilder auth)
        Set user details service to UserService
        Set password encoder to the one configured
END class
// Controller - UserController.java
START class UserController
    METHOD register(@RequestBody User user)
        IF username already exists
            RETURN "Username already taken"
        Encrypt user's password
        Save user via UserService
        RETURN "User registered successfully"

    METHOD login(@RequestParam String username, @RequestParam String password)
        Fetch user by username from UserService
        IF user exists AND password matches hashed password
            RETURN "Login successful"
        ELSE
            RETURN "Invalid username or password"
END class
// Service - UserService.java
START class UserService
    Inject UserRepository and PasswordEncoder
    
    METHOD registerUser(User user)
        Encrypt user's password using PasswordEncoder
        Save user via UserRepository
        RETURN saved user

    METHOD findUserByUsername(String username)
        RETURN userRepository.findByUsername(username)
END class
// Repository - UserRepository.java
START interface UserRepository extends JpaRepository<User, Long>
    METHOD findByUsername(String username)
        # Custom query to find a user by username
END interface
// Model - User.java
START class User
    @Entity annotation for database mapping
    
    Define fields:
        Long id (primary key, auto-generated)
        String username
        String password (hashed)

    Use appropriate JPA annotations (@Id, @Column, etc.)
END class
// Password Encoder - PasswordEncoder
START configuration
    Define PasswordEncoder bean in WebSecurityConfig
    Use BCrypt for hashing
    
    Encrypt password on user registration
    Verify hashed password during login
END configuration
