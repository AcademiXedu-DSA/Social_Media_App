package com.example.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtRequestFilter jwtRequestFilter;

    // Inject JwtRequestFilter to add it to the security filter chain
    public SecurityConfig(JwtRequestFilter jwtRequestFilter) {
        this.jwtRequestFilter = jwtRequestFilter;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())  // Disabling CSRF protection
            .authorizeHttpRequests(authorizeRequests -> 
                authorizeRequests
                    .requestMatchers("/auth/register", "/auth/login").permitAll()  // Public endpoints
                    .requestMatchers("/h2-console/**").permitAll()  // Allow access to H2 console
                    .anyRequest().authenticated()  // Require authentication for all other requests
            )
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // Disable sessions for stateless APIs
            .headers(headers -> 
                headers.frameOptions().disable())  // Disable X-Frame-Options to allow H2 console in iframe
            .cors(cors -> cors.configurationSource(corsConfigurationSource()));  // Enable CORS for all API requests

        // Add JWT filter for authentication handling
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();  // Return the HttpSecurity object
    }

    // Configuring CORS to allow specific origins (for example)
    private org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
        org.springframework.web.cors.CorsConfiguration configuration = new org.springframework.web.cors.CorsConfiguration();
        configuration.addAllowedOrigin("*");  // Allow all origins (for development purposes)
        configuration.addAllowedMethod("*");  // Allow all methods
        configuration.addAllowedHeader("*");  // Allow all headers
        org.springframework.web.cors.UrlBasedCorsConfigurationSource source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
