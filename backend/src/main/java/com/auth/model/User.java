package com.auth.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import javax.persistence.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role = "USER";
}


// package com.auth.model;

// import lombok.Data;
// import lombok.NoArgsConstructor;
// import lombok.AllArgsConstructor;
// import org.springframework.data.annotation.Id;
// import org.springframework.data.mongodb.core.mapping.Document;

// @Data
// @NoArgsConstructor
// @AllArgsConstructor
// @Document(collection = "users") // Maps this class to the "users" collection in MongoDB
// public class User {
//     @Id
//     private String id; // MongoDB's primary key is a string (_id).

//     private String username; // Unique username for the user.

//     private String password; // Password of the user (should be encrypted).

//     private String role = "USER"; // Default role assigned to the user.
// }
