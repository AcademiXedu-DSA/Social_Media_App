package com.auth.repository;

import com.auth.model.Tweet;
import com.auth.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TweetRepository extends JpaRepository<Tweet, Long> {
                 //most recent tweets appear first
    Page<Tweet> findAllByOrderByTimestampDesc(Pageable pageable);
    Page<Tweet> findByUserOrderByTimestampDesc(User user, Pageable pageable);
}
// In a social media app, this method could retrieve the latest tweets for a homepage feed, paginated to load 10 tweets at a time.


// package com.auth.repository;

// import com.auth.model.Tweet;
// import com.auth.model.User;
// import org.springframework.data.domain.Page;
// import org.springframework.data.domain.Pageable;
// import org.springframework.data.mongodb.repository.MongoRepository;
// import org.springframework.stereotype.Repository;

// @Repository
// public interface TweetRepository extends MongoRepository<Tweet, String> {
//     // Most recent tweets appear first
//     Page<Tweet> findAllByOrderByTimestampDesc(Pageable pageable);

//     // Find tweets by user, most recent first
//     Page<Tweet> findByUserOrderByTimestampDesc(User user, Pageable pageable);
// }
