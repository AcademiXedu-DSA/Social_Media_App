package com.example.jwtsecurity.repository;

import com.example.jwtsecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * JPA repository for managing User entities.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * Finds a user by their username.
     * @param username The username.
     * @return An Optional containing the user if found, Optional.empty() otherwise.
     */
    Optional<User> findByUsername(String username);

    /**
     * Checks if a user with the given username already exists.
     * @param username The username.
     * @return True if a user with the given username exists, false otherwise.
     */
    boolean existsByUsername(String username);
}
