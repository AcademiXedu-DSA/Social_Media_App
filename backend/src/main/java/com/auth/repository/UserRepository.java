package com.auth.repository;

import com.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
}


// package com.auth.repository;

// import com.auth.model.User;
// import org.springframework.data.mongodb.repository.MongoRepository;
// import org.springframework.stereotype.Repository;
// import java.util.Optional;

// @Repository
// public interface UserRepository extends MongoRepository<User, String> {
//     Optional<User> findByUsername(String username);
//     boolean existsByUsername(String username);
// }
