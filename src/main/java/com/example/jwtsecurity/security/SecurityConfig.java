package com.example.jwtsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // Injecting JwtRequestFilter that handles JWT token validation
    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Configure CORS (Cross-Origin Resource Sharing) and disable CSRF (Cross-Site Request Forgery)
        http.cors().and().csrf().disable()
            // Authorize requests for specific endpoints
            .authorizeRequests()
            .antMatchers("/api/auth/**").permitAll()  // Allow unrestricted access to authentication endpoints
            .antMatchers("/h2-console/**").permitAll()  // Allow unrestricted access to H2 database console
            .antMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()  // Allow access to API docs and Swagger UI
            .anyRequest().authenticated()  // Any other request must be authenticated
            .and()
            .headers().frameOptions().disable()  // Disable frame options to allow H2 console to be loaded in a frame
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);  // Ensure session management is stateless (no server-side sessions)

        // Add the JwtRequestFilter before UsernamePasswordAuthenticationFilter to intercept JWT tokens
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    // Bean for password encoding using BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // Use BCrypt to encode passwords
    }

    // Bean to configure CORS policy to allow requests from the frontend (localhost:3000)
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));  // Allow requests from React frontend
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));  // Allow these HTTP methods
        configuration.setAllowedHeaders(Arrays.asList("*"));  // Allow all headers
        configuration.setAllowCredentials(true);  // Allow credentials (e.g., cookies, authorization headers)

        // Register the CORS configuration for all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
