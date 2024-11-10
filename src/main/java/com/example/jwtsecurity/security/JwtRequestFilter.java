package com.example.jwtsecurity.security;

import com.example.jwtsecurity.service.SessionManager;
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

/**
 * This filter intercepts every incoming request and validates the JWT token present in the Authorization header.
 * If the token is valid and the session is active, it sets the Spring Security context with the authenticated user details.
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private SessionManager sessionManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        // Extract JWT from Authorization header if present and starts with "Bearer "
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);
            } catch (ExpiredJwtException e) {
                logger.warn("JWT Token has expired");
            }
        }

        // If username is found and user is not already authenticated
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Check if session is valid using SessionManager
            if (sessionManager.isSessionValid(username, jwt)) {
                // Create a UserDetails object.  Note: In a real application, you would fetch user details from the database here.
                UserDetails userDetails = new User(username, "", new ArrayList<>());

                // Validate the token using JwtUtil
                if (jwtUtil.validateToken(jwt, userDetails)) {
                    // Create and set Authentication token in Security Context
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        }
        chain.doFilter(request, response);
    }
}
