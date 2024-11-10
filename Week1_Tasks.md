``` pom
auth-application/
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── auth/
│                   ├── controller/
│                   │   └── AuthController.java
│                   ├── exception/
│                   │   ├── GlobalExceptionHandler.java
│                   │   ├── InvalidCredentialsException.java
│                   │   └── UserAlreadyExistsException.java
│                   ├── model/
│                   │   └── User.java 
│                   ├── repository/
│                   │   └── UserRepository.java
│                   ├── security/
│                   │   ├── JwtRequestFilter.java
│                   │   ├── JwtUtil.java
│                   │   └── SecurityConfig.java
│                   └── service/
│                       ├── AuthService.java
│                       └── SessionManager.java
├── pom.xml
```

## **Table of Contents**

1. [Project Overview](#1-project-overview)
2. [Project Setup](#2-project-setup)
3. [Defining the User Entity](#3-defining-the-user-entity)
4. [Creating the User Repository](#4-creating-the-user-repository)
5. [Implementing the Authentication Service](#5-implementing-the-authentication-service)
6. [Managing Sessions](#6-managing-sessions)
7. [JWT Utility Class](#7-jwt-utility-class)
8. [JWT Request Filter](#8-jwt-request-filter)
9. [Configuring Spring Security](#9-configuring-spring-security)
10. [Building the Authentication Controller](#10-building-the-authentication-controller)
11. [Global Exception Handling](#11-global-exception-handling)
12. [API Documentation with Swagger](#12-api-documentation-with-swagger)
13. [Running the Application](#13-running-the-application)
14. [Conclusion](#14-conclusion)

---

## **1. Project Overview**

### **Objective**

Build a secure authentication service using **Spring Boot** that allows users to **register**, **log in**, and **log out**. The service will utilize **JWT (JSON Web Tokens)** for stateless session management and adhere to best security practices.

### **Key Components** 

- **User Entity:** Represents the users in the system.
- **User Repository:** Handles data persistence for users.
- **Authentication Service:** Contains business logic for authentication.
- **Session Manager:** Manages user sessions.
- **JWT Utility:** Generates and validates JWT tokens.
- **JWT Request Filter:** Intercepts requests to validate JWTs.
- **Security Configuration:** Configures Spring Security settings.
- **Authentication Controller:** Exposes REST endpoints for authentication.
- **Global Exception Handler:** Manages application-wide exceptions.
- **API Documentation:** Provides interactive API docs using Swagger.

---

## **2. Project Setup**

### **Step 1: Initialize the Spring Boot Project**

1. Navigate to [Spring Initializr](https://start.spring.io/).
2. Configure the project with the following settings:
   - **Project:** Maven Project
   - **Language:** Java
   - **Spring Boot:** 2.7.x or later
   - **Group:** `com.auth`
   - **Artifact:** `auth-application`
   - **Name:** `AuthApplication`
   - **Dependencies:**
     - Spring Web
     - Spring Security
     - Spring Data JPA
     - H2 Database
     - Lombok
     - Springfox Swagger UI

3. Click **Generate** to download the project.
4. Extract the downloaded archive and open it in your preferred IDE (e.g., IntelliJ IDEA, Eclipse).

### **Step 2: Configure Lombok**

Ensure that Lombok is correctly set up in your IDE to handle annotations like `@Data`, `@NoArgsConstructor`, and `@AllArgsConstructor`.

- **IntelliJ IDEA:** Install the Lombok plugin via `Settings > Plugins`.
- **Eclipse:** Install the Lombok plugin by downloading the Lombok jar and running it with the Eclipse executable.

---

## **3. Defining the User Entity**

### **Learning Objectives**

- Understand JPA annotations and their roles.
- Define entity constraints like uniqueness and non-nullability.
- Set default values for entity fields.

### **Task**

Complete the `User.java` file by filling in the missing annotations and fields.

### **Instructions**

1. Navigate to `src/main/java/com/auth/model/User.java`.
2. Replace the existing code with the following, filling in the blanks marked by `___`.

### **Code with Blanks**

```java
// File: src/main/java/com/auth/model/User.java
package com.auth.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import javax.persistence.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity_
@Table__(name = "users")
public class User {
    @Id___
    @GeneratedValue__(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column__(unique = true, nullable = false)
    private String username;

    @Column__(nullable = false)
    private String password;

    @Column__(nullable = false)
    private String role = "USER";
}
```

### **Guidance**

- **Annotations to Add:**
  - `@Entity`
  - `@Table`
  - `@Id`
  - `@GeneratedValue`
  - `@Column`

---

## **4. Creating the User Repository**

### **Learning Objectives**

- Understand the role of repositories in Spring Data JPA.
- Define custom query methods.

### **Task**

Complete the `UserRepository.java` by adding methods to find a user by username and check if a username exists.

### **Instructions**

1. Navigate to `src/main/java/com/auth/repository/UserRepository.java`.
2. Replace the existing code with the following, filling in the blanks marked by `___`.

### **Code with Blanks**

```java
// File: src/main/java/com/auth/repository/UserRepository.java
package com.auth.repository;

import com.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long __> {
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
}
```

### **Guidance**

- **Extend `JpaRepository` with the correct type parameters.**

---

## **5. Implementing the Authentication Service**

### **Learning Objectives**

- Implement business logic for user registration, authentication, and logout.
- Utilize dependency injection with `@Autowired`.
- Handle password encryption.

### **Task**

Complete the `AuthService.java` by implementing the `register`, `authenticate`, and `logout` methods.

### **Instructions**

1. Navigate to `src/main/java/com/auth/service/AuthService.java`.
2. Replace the existing code with the following, filling in the blanks marked by `___`.

### **Code with Blanks**

```java
// File: src/main/java/com/auth/service/AuthService.java
package com.auth.service;

import com.auth.model.User;
import com.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository ;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SessionManager sessionManager;

    public User register(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Username already exists");
        }
        
        // Set default role if not specified
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("USER");
        }
        
        // Encrypt password before storing
        user.setPassword(passwordEncoder.___(user.getPassword()));
        return userRepository.save(user);
    }

    public Optional<User> authenticate(String username, String password) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        
        if (userOpt.isPresent() && passwordEncoder.matches(password, userOpt.get().getPassword())) {
            return userOpt;
        }
        
        return useropt___;
    }

    public void logout(String username) {
        sessionManager.invalidatesession__(username);
    }
}
```

### **Guidance**

- **Dependencies to Inject:**
  - `UserRepository`
  - `PasswordEncoder`
  - `SessionManager`
- **Methods to Implement:**
  - `register`: Checks for existing usernames, sets default roles, encrypts passwords, and saves the user.
  - `authenticate`: Verifies user credentials.
  - `logout`: Invalidates the user's session.

---

## **6. Managing Sessions**

### **Learning Objectives**

- Understand session management in a stateless authentication system.
- Utilize thread-safe collections for concurrent access.

### **Task**

Complete the `SessionManager.java` by implementing methods to create, invalidate, and validate sessions.

### **Instructions**

1. Navigate to `src/main/java/com/auth/service/SessionManager.java`.
2. Replace the existing code with the following, filling in the blanks marked by `___`.

### **Code with Blanks**

```java
// File: src/main/java/com/auth/service/SessionManager.java
package com.auth.service;

import org.springframework.stereotype.Component;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class SessionManager {
    private final ConcurrentMap<String, String> userSessions = new ConcurrentHashMap<>();

    public void createSession(String username, String token) {
        userSessions._put__(username, token);
    }

    public void invalidateSession(String username) {
        userSessions.remove___(username);
    }

    public boolean isSessionValid(String username, String token) {
        String storedToken = userSessions.get__(username);
        return storedToken != null && storedToken.equals__(token);
    }
}
```

### **Guidance**

- **Use `ConcurrentHashMap` for thread safety.**
- **Implement methods to handle session creation, invalidation, and validation.**

---

## **7. JWT Utility Class**

### **Learning Objectives**

- Understand JWT structure and purpose.
- Implement token generation and validation.
- Handle token claims and expiration.

### **Task**

Complete the `JwtUtil.java` by implementing methods to generate tokens, extract information, and validate tokens.

### **Instructions**

1. Navigate to `src/main/java/com/auth/security/JwtUtil.java`.
2. Replace the existing code with the following, filling in the blanks marked by `___`.

### **Code with Blanks**

```java
// File: src/main/java/com/auth/security/JwtUtil.java
package com.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {
    private String SECRET_KEY = "your_secret_key_here";
    private int TOKEN_VALIDITY = 3600 * 5; // 5 hours

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim___(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims___(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                   .setSigningKey(SECRET_KEY)
                   .parseClaimsJws(token)
                   .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration___(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken___(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                   .setClaims(claims)
                   .setSubject(subject)
                   .setIssuedAt(new Date(System.currentTimeMillis()))
                   .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY * 1000))
                   .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                   .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extraxtUsername___(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired___(token));
    }
}
```

### **Guidance**

- **Implement methods to handle claims, token extraction, generation, and validation.**

---

## **8. JWT Request Filter**

### **Learning Objectives**

- Intercept HTTP requests to validate JWT tokens.
- Set authentication in the security context for valid tokens.

### **Task**

Complete the `JwtRequestFilter.java` by implementing the `doFilterInternal` method to extract and validate JWT tokens.

### **Instructions**

1. Navigate to `src/main/java/com/auth/security/JwtRequestFilter.java`.
2. Replace the existing code with the following, filling in the blanks marked by `___`.

### **Code with Blanks**

```java
// File: src/main/java/com/auth/security/JwtRequestFilter.java
package com.auth.security;

import com.auth.service.SessionManager;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@Component
public class JwtRequestFilter extends OnceperRequestFilter___ {
    
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private SessionManager sessionManager;

    @Override
    protected void doFilterInternal___(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith___("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);
            } catch (ExpiredJwtException e) {
                logger.warn("JWT Token has expired");
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (sessionManager.isSessionValid___(username, jwt)) {
                UserDetails userDetails = new User(username, "", new ArrayList<>());

                if (jwtUtil._validateToken__(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource()._buildDetails__(request));
                    SecurityContextHolder.getContext()._setAuthentication__(authToken);
                }
            }
        }
        ___;
    }
}
```

### **Guidance**

- **Extend `OncePerRequestFilter`.**
- **Implement the `doFilterInternal` method.**
- **Extract and validate JWT tokens from the `Authorization` header.**
- **Set authentication in the security context for valid tokens.**

---

## **9. Configuring Spring Security**

### **Learning Objectives**

- Configure Spring Security settings for authentication and authorization.
- Integrate JWT filters into the security filter chain.
- Set up CORS and CSRF configurations.

### **Task**

Complete the `SecurityConfig.java` by configuring security settings and integrating the `JwtRequestFilter`.

### **Instructions**

1. Navigate to `src/main/java/com/auth/security/SecurityConfig.java`.
2. Replace the existing code with the following, filling in the blanks marked by `___`.

### **Code with Blanks**

```java
// File: src/main/java/com/auth/security/SecurityConfig.java
package com.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends ___ {
    
    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Override
    protected void ___(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()
            .antMatchers("/h2-console/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .headers().frameOptions().disable()
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtRequestFilter, ___);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BcryptPasswordEncoder___();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000")); // React frontend
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration___("/**", configuration);
        return source;
    }
}
```

### **Guidance**

- **Extend `WebSecurityConfigurerAdapter`.**
- **Override the `configure` method to set up security settings.**
- **Define beans for `PasswordEncoder` and `CorsConfigurationSource`.**

---

## **10. Building the Authentication Controller**

### **Learning Objectives**

- Expose REST endpoints for user registration, login, and logout.
- Handle HTTP requests and responses.
- Integrate with the service layer and JWT utilities.

### **Task**

Complete the `AuthController.java` by implementing the endpoints with appropriate request mappings and logic.

### **Instructions**

1. Navigate to `src/main/java/com/auth/controller/AuthController.java`.
2. Replace the existing code with the following, filling in the blanks marked by `___`.

### **Code with Blanks**

```java
// File: src/main/java/com/auth/controller/AuthController.java
package com.auth.controller;

import com.auth.model.User;
import com.auth.security.JwtUtil;
import com.auth.service.AuthService;
import com.auth.service.SessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private SessionManager sessionManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        try {
            User registeredUser = authService.register___(user);
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(registeredUser.getUsername___())
                .password("")
                .authorities(registeredUser.getRole___())
                .build();

            String token = jwtUtil.generateToken___(userDetails);
            sessionManager._createSession__(registeredUser.___(), token);

            Map<String, Object> response = new HashMap<>();
            response.put("message", "User registered successfully");
            response.put("token", token);
            response.put("username", registeredUser.getUsername___());
            response.put("role", registeredUser._getRole__());
            
            return ResponseEntity.ok___(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        if (!credentials.containsKey("username") || !credentials.containsKey("password")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username and password are required"));
        }

        String username = credentials.get("username");
        String password = credentials.get("password");

        try {
            Optional<User> userOpt = authService.authenticate___(username, password);
            
            if (userOpt.ispresent___()) {
                User user = userOpt._get__();
                UserDetails userDetails = org.springframework.security.core.userdetails.User
                    .withUsername(username)
                    .password("")
                    .authorities(user._getRole__())
                    .build();

                String token = jwtUtil._generateToken__(userDetails);
                sessionManager._createSession__(username, token);

                Map<String, Object> response = new HashMap<>();
                response.put("token", token);
                response.put("username", username);
                response.put("role", user.getRole___());
                return ResponseEntity.ok___(response);
            }

            return ResponseEntity.badRequest().body(Map.of("error", "Invalid credentials"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Authentication failed: " + e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or missing token"));
        }

        try {
            String jwt = token.substring(7);
            String username = jwtUtil.extractUsername___(jwt);
            
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(username)
                .password("")
                .authorities("USER")
                .build();

            if (!jwtUtil.validateToken___(jwt, userDetails)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired token"));
            }

            authService._logout__(username);
            return ResponseEntity.ok().body(Map.of("message", "Logged out successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Logout failed: " + e.getMessage()));
        }
    }
}
```

### **Guidance**

- **Endpoints to Implement:**
  - `POST /api/auth/register`: User registration.
  - `POST /api/auth/login`: User authentication.
  - `POST /api/auth/logout`: User logout.
- **Methods to Complete:**
  - `authService.register(user)`
  - Access user properties like `getUsername()` and `getRole()`.
  - Generate token using `jwtUtil.generateToken(userDetails)`.
  - Manage session with `sessionManager.createSession(username, token)`.
  - Return responses using `ResponseEntity.ok(response)`.

---

## **11. Global Exception Handling**

### **Learning Objectives**

- Implement centralized exception handling using `@ControllerAdvice`.
- Create custom exception classes for specific error scenarios.

### **Task**

Create custom exceptions and a global exception handler using `@ControllerAdvice`.

### **Instructions**

1. **Create Custom Exception Classes:**

   - **`UserAlreadyExistsException.java`:**
   
     ```java
     // File: src/main/java/com/auth/exception/UserAlreadyExistsException.java
     package com.auth.exception;
     
     public class UserAlreadyExistsException extends RuntimeException {
         public UserAlreadyExistsException(String message) {
             super(message);
         }
     }
     ```
   
   - **`InvalidCredentialsException.java`:**
   
     ```java
     // File: src/main/java/com/auth/exception/InvalidCredentialsException.java
     package com.auth.exception;
     
     public class InvalidCredentialsException extends RuntimeException {
         public InvalidCredentialsException(String message) {
             super(message);
         }
     }
     ```

2. **Create the Global Exception Handler:**

   ```java
   // File: src/main/java/com/auth/exception/GlobalExceptionHandler.java
   package com.auth.exception;
   
   import org.springframework.http.HttpStatus;
   import org.springframework.http.ResponseEntity;
   import org.springframework.web.bind.annotation.*;
   import java.util.Map;
   
   @ControllerAdvice
   public class GlobalExceptionHandler {
   
       @ExceptionHandler(UserAlreadyExistsException.class)
       public ResponseEntity<?> handleUserAlreadyExists(UserAlreadyExistsException ex) {
           return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", ex.getMessage()));
       }
   
       @ExceptionHandler(InvalidCredentialsException.class)
       public ResponseEntity<?> handleInvalidCredentials(InvalidCredentialsException ex) {
           return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", ex.getMessage()));
       }
   
       @ExceptionHandler(Exception.class)
       public ResponseEntity<?> handleGeneralException(Exception ex) {
           return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(Map.of("error", "An unexpected error occurred."));
       }
   }
   ```

### **Guidance**

- **Custom Exceptions:**
  - **`UserAlreadyExistsException`:** Thrown when attempting to register a user with a username that already exists.
  - **`InvalidCredentialsException`:** Thrown when user authentication fails due to invalid credentials.
  
- **Global Exception Handler (`GlobalExceptionHandler`):**
  - **`@ControllerAdvice`:** Indicates that the class provides centralized exception handling across all controllers.
  - **`@ExceptionHandler`:** Specifies the type of exception to handle.
  - **Response Structure:** Returns a `Map` with an `"error"` key containing the error message.
  - **HTTP Status Codes:**
    - **`CONFLICT (409)`:** For `UserAlreadyExistsException`.
    - **`UNAUTHORIZED (401)`:** For `InvalidCredentialsException`.
    - **`INTERNAL_SERVER_ERROR (500)`:** For all other exceptions.

---

## **12. API Documentation with Swagger**

### **Learning Objectives**

- Integrate Swagger for interactive API documentation.
- Understand how to access and use Swagger UI.

### **Task**

Configure Swagger in the project by adding necessary dependencies and configuration classes.

### **Instructions**

1. **Add Swagger Dependency:**

   - **For Maven (`pom.xml`):**
   
     ```xml
     <dependency>
         <groupId>io.springfox</groupId>
         <artifactId>springfox-boot-starter</artifactId>
         <version>3.0.0</version>
     </dependency>
     ```
   
   - **For Gradle (`build.gradle`):**
   
     ```groovy
     implementation 'io.springfox:springfox-boot-starter:3.0.0'
     ```

2. **Create Swagger Configuration Class:**

   ```java
   // File: src/main/java/com/auth/config/SwaggerConfig.java
   package com.auth.config;
   
   import org.springframework.context.annotation.Bean;
   import org.springframework.context.annotation.Configuration;
   import springfox.documentation.builders.PathSelectors;
   import springfox.documentation.builders.RequestHandlerSelectors;
   import springfox.documentation.spi.DocumentationType;
   import springfox.documentation.spring.web.plugins.Docket;
   import springfox.documentation.swagger2.annotations.EnableSwagger2;
   
   @Configuration
   @EnableSwagger2
   public class SwaggerConfig {
       @Bean
       public Docket api() {
           return new Docket(DocumentationType.SWAGGER_2)
                   .select()
                   .apis(RequestHandlerSelectors.basePackage("com.auth.controller"))
                   .paths(PathSelectors.any())
                   .build();
       }
   }
   ```

3. **Access Swagger UI:**

   Once the application is running, navigate to `http://localhost:8080/swagger-ui/` to access the interactive API documentation.

### **Guidance**

- **Swagger Integration:**
  - **Dependency:** Adds the Swagger starter to the project, enabling automatic API documentation generation.
  - **Configuration Class (`SwaggerConfig`):**
    - **`@Configuration`:** Marks the class as a source of bean definitions.
    - **`@EnableSwagger2`:** Enables Swagger support in the application.
    - **`Docket` Bean:** Configures Swagger to scan the `com.auth.controller` package for API endpoints and includes all paths.
  
- **Swagger UI:** Provides a user-friendly interface to interact with and test the API endpoints without the need for external tools like Postman.

---

## **13. Running the Application**

### **Learning Objectives**

- Build and run the Spring Boot application.
- Access and interact with API endpoints using Swagger UI.
- Utilize the H2 console for database inspection.

### **Task**

Follow the steps below to build and run the application, and test the authentication endpoints.

### **Instructions**

1. **Ensure All Code is Correct:**
   - Verify that all previous sections have been completed without syntax errors.

2. **Build the Project:**
   
   - **Using Maven:**
   
     ```bash
     mvn clean install
     ```
   
   - **Using Gradle:**
   
     ```bash
     gradle build
     ```

3. **Run the Application:**
   
   - **Using Maven:**
   
     ```bash
     mvn spring-boot:run
     ```
   
   - **Using Gradle:**
   
     ```bash
     gradle bootRun
     ```
   
   - **Alternatively:** Run the `AuthApplication.java` class directly from your IDE.

4. **Access H2 Console (Development Only):**
   
   - Navigate to `http://localhost:8080/h2-console`.
   - **JDBC URL:** `jdbc:h2:mem:authdb`
   - **Username:** `sa`
   - **Password:** *(leave blank)*
   - Click **Connect** to access the in-memory database.

5. **Access Swagger UI:**
   
   - Navigate to `http://localhost:8080/swagger-ui/` to view and interact with the API endpoints.

6. **Testing the Endpoints:**
   
   - **Register a New User:**
     
     - **Endpoint:** `POST /api/auth/register`
     - **Payload:**
       
       ```json
       {
         "username": "john_doe",
         "password": "securePassword123"
       }
       ```
   
   - **Login:**
     
     - **Endpoint:** `POST /api/auth/login`
     - **Payload:**
       
       ```json
       {
         "username": "john_doe",
         "password": "securePassword123"
       }
       ```
   
   - **Logout:**
     
     - **Endpoint:** `POST /api/auth/logout`
     - **Headers:**
       - `Authorization: Bearer <JWT_TOKEN>`
     - **Replace `<JWT_TOKEN>`** with the token received upon successful login.

### **Guidance**

- **Replace `<JWT_TOKEN>`** with the actual token obtained from the login response.

---

## **14. Conclusion**

Congratulations! You have successfully built a **Spring Boot Authentication Service** with **JWT-based security**. This fill-in-the-blank tutorial guided you through setting up the project, defining entities and repositories, implementing services and controllers, configuring security, handling exceptions, and documenting APIs with Swagger.

### **Key Takeaways**

- **Spring Boot:** Simplifies the development of stand-alone, production-grade Spring-based applications.
- **JWT:** Enables stateless authentication, reducing server-side session management complexities.
- **Spring Security:** Provides robust security features for authentication and authorization.
- **Exception Handling:** Ensures consistent and meaningful error responses.
- **Swagger:** Enhances API usability through interactive documentation.

### **Next Steps**

- **Enhance Security:**
  - Implement features like **refresh tokens**, **account verification**, and **role-based access control (RBAC)**.
- **Persistent Sessions:**
  - Move from in-memory session management to distributed caches like **Redis** for scalability.
- **Testing:**
  - Develop comprehensive **unit** and **integration tests** to ensure application reliability.
- **Deployment:**
  - Prepare the application for **production environments** with proper configurations and security measures.

### **Further Enhancements [Future Scope]**

1. **Refresh Tokens:**
   - Implement a mechanism to issue refresh tokens, allowing users to obtain new access tokens without re-authenticating.
2. **Password Reset Functionality:**
   - Allow users to reset their passwords via email verification or security questions.
3. **Account Verification:**
   - Require users to verify their email addresses upon registration.
4. **User Profile Management:**
   - Enable users to update their profile information, such as email, name, and password.
5. **Role Management and RBAC:**
   - Define multiple roles (e.g., `ADMIN`, `USER`, `MODERATOR`) and secure endpoints based on user roles.
6. **Audit Logging:**
   - Track and log important events (e.g., login attempts, password changes) for security auditing and monitoring.
7. **API Rate Limiting:**
   - Prevent abuse by limiting the number of requests a user can make to certain endpoints within a specified timeframe.
8. **Internationalization (i18n):**
   - Support multiple languages for API responses and error messages to cater to a diverse user base.
9. **API Versioning:**
    - Implement versioning (e.g., `/api/v1/auth`) to manage and maintain different API versions seamlessly.

