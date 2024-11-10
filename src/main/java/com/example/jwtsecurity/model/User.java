package com.example.jwtsecurity.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import javax.persistence.*;

/**
 * Represents a user in the system.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User {
    /**
     * The unique identifier for the user.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * The user's username, must be unique.
     */
    @Column(unique = true, nullable = false)
    private String username;

    /**
     * The user's password.
     */
    @Column(nullable = false)
    private String password;

    /**
     * The user's role (default is USER).
     */
    @Column(nullable = false)
    private String role = "USER";
}
