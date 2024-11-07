# Social_Media_App

**FLOW-CHART**

                                                  -------------
                                                 |             |
                                                 |    USER     |
                                                  -------------
                                                        |
                                                        v
                                                -------------------------
                                               | **AuthController.java** |
                                               |      /api/auth          |
                                                -------------------------
                                                        |
                                                        v
                        ------------------         ----------------            ------------------
                        |Tries to Register|        |Tries to Login|            | Tries to Logout|
                        |  /Register      |        |    /Login    |            |      /Logout   |
                        ------------------         ----------------             -----------------
                             |                           |                             |
                             v                           v                             v
                        -------------------------   -------------------------   --------------------------
                       | plain pasw-->Hashed Pass|  |  verify entered pasw  |   |make session inactive in| 
                       | use Bcrypt Algo generate|  | with hashed pasw in db|   |session manager         |
                       | JWT **AuthService.java**|  |  **AuthService.java** |   |**sessionmanager.java** |  
                       ---------------------------  -------------------------   --------------------------
                             |                               |                         
                             v                               v
                         ----------------           -----------------------
                        | Save user in db|         |    Generate JWT token |
                        |                |         | using HS256 Algorithm | 
                         ----------------          |   in **JwtUtil.java** |
                                                    -----------------------




<!-- FILES WE HAVE USED  -->
 **AuthController**
 **User.java**
 **UserRespository**
**JwtRequestFilter.java**
**JwtUtil.java**
**SecurityConfig.java**
**AuthService.java**
**SessionManager.java**
<!-- Set Up Project Dependencies -->
1.Include dependencies for 
---> Spring Boot, 
---> Spring Security,
---> JPA, H2db(or other databases)
---> BCrypt for password hashing, 
---> JSON Web Token (JWT) libraries


<!-- AuthApplication.java -->
----> Starting of the application

<!-- Set Up Database for User Information -->
**user.java**
1.Create a user table it will store info. about each user in **User.java** 
2.table contains 'username','password' and 'role'
3.username--->should be unique
4.password(string)--->store the hashedpassword 
5.role(String)----> such as "USER" / "ADMIN"
6.Use a database like H2db
7.add dependency to pom.xml and configure to **application.properties** in resources

<!-- AUthcontroller -->
lets take 3 endpoints
1. /api/auth   it is abase url
2. /register
3./login
4. /logout

<!-- AuthService -->

1.Register:
    Check if the username exists, if not hash the password using BCrypt, and save the user using userRepository.
2.Authenticate:
    Validate the user’s credentials by comparing the provided password with the stored hashed password.
3.Logout:
    Invalidate the session by removing the username-token pair from SessionManager.


<!-- USER-REGISTRATION -->
----> create '/register' endpoint in **authcontroller**
1.Add a method findByUsername(username) from **userRepository.java** to check if a user exists by username and return the user if found.
----> return a message "USER ALREADY EXISTS!PLEASE LOGIN"
----> add  bcrypt dependency in pom.xml
2.if user is not found then password must be converted into hashed password by using bcrypt alogorithm before storing in db
**Hashing the Password:**
The hashPassword method takes a plain text password and uses BCrypt.hashpw to create a secure hash.
**BCrypt.gensalt()** generates a salt to add extra randomness to the hash, making it more secure.

connected to **UserService.java**(registerUser). 
3.return a message "registration successfull"
****for example***
username:syam;
password:syam123 ----->uses BCrypt.hashpw to create a secure hash
--->hashedpassword look like in db **$2a$10$eB0UVQzP6X1pF7U/ul8G.eGwV5O9uY6YZ4xZbS.jCj6ZsN9lUMNEi**
4.Store the username and password_hash in the database


<!--USER-AUTHENCATION -->
1.create '/login' endpoint in authcontroller
2.Now Auth Controller calls the authenicateUser method in Auth Service 
3.if the user tries to login.now login password is converted into hashed password by using bcrypt algorithm
this hashed password compare with stored hashed password in db
**Verifying the Password:**
--->The checkPassword method takes a plain text password and the hashed password from storage.
**BCrypt.checkpw** compares the plain password with the hash, returning true if they match.

4.if they match 'the user is authenicated'
5.if they doesnot match return a "invalid credentials"
--->add jwt dependency in pom.xml
6.if user succesfully login we should  generate a jwt(json web token) from **jwtUtil.java**
7.Use JWT to secure endpoints by verifying the token on each request.
8.Jwt token along with username should be stored in SessionManager using HASH MAP Data structure


<!-- USER LOGOUT -->
1.Create a /logout endpoint in AuthController to handle user logout requests.
2.AuthController calls the logout method in AuthService.
3.Check if the session exists in SessionManager (using the username or JWT token to find the entry).
4.If a session is found for the user, remove it from **SessionManager**.
Return a message like "USER LOGGED OUT SUCCESSFULLY". 

<!-- jwtutil.java -->

**Steps to Generate a JWT Token**

Claims are pieces of information about the user or the token itself, such as:
--->Standard Claims: sub (subject, typically the username), iat (issued at timestamp), exp (expiration timestamp).
--->Custom Claims: Application-specific claims (e.g., roles, permissions).

1. Set Token Validity:
--->Set an expiration time for the token using exp claim. This controls how long the token will be valid (e.g., 1 hour, 24 hours).

2. Sign the Token:
Use a signing algorithm (e.g., HMAC SHA-256 or RSA) and a secure key to sign the token. The signature ensures that the token has not been tampered with.

3. Generate the Token:
Combine the header, payload (claims), and signature, and encode them to form the JWT.

finnaly,after user authentication to generate a token that will be sent to the client and used to authenticate future requests.

----> we add the JJWT (Java JWT) library  in pom.xml
# Importing required libraries for JWT creation and signing:

--> import io.jsonwebtoken.Jwts;
-->import io.jsonwebtoken.SignatureAlgorithm;
--->import io.jsonwebtoken.security.Keys;
-->import java.security.Key;
--->import java.util.Date;


<!-- USER LOGOUT -->
1.Create a /logout endpoint in AuthController to handle user logout requests.
2.AuthController calls the logout method in AuthService.
3.Check if the session exists in SessionManager (using the username or JWT token to find the entry).
4.If a session is found for the user, remove it from **SessionManager**.
Return a message like "USER LOGGED OUT SUCCESSFULLY". 

<!-- sessionmanager.java -->
By using 'Hash-Map' data-structure we can store session of user in ""sessionManager"
1.Create Session:
    Store a new session with the username-token pair.
2.Invalidate Session:
    Remove the session associated with the user by deleting the username-token pair.
3.Check Session Validity:
    Verify if the session for a given username and token is still valid.

 <!-- Security Config -->
1.Inorder to protect the urls we use **Security Config**
2.Set up the URLs which should be public like /register,/login and private like /profile, /dashboard. Only authenticated users should access private URLs.
3.Create a **JwtRequestFilter** to intercept each request and validate the JWT token, ensuring it is not expired and is correctly signed.
4.If the token is valid then only the user is allowed to private endpoints like dashboard. 


<!-- SessionManager.java -->
We use SessionManager class to store user sessions. This will usually be a HashMap where the key is the JWT token , and the value is the username.
It contains methods like
1. **createSession**
Purpose: To add a new session when a user logs in successfully.
Function: Stores the user’s JWT and username
Example Use: When a user logs in, their JWT and username are stored in the SessionManager to track active sessions.

2. **invalidateSession**
Purpose: To remove a session when a user logs out or when a session needs to be invalidated for security reasons.
Function: Deletes the JWT from the session manager, making it invalid for future requests.
Example Use: When a user logs out, calling this method removes their JWT, effectively logging them out by invalidating their session.

3. **isSessionValid**
Purpose: To check if a session is active for a given JWT.
Function: Looks up the JWT in the session manager to see if it is still valid and active.
Example Use: Before processing a request, you can call this method to verify if the user’s JWT is still valid and hasn’t been invalidated

<!-- JwtRequestFilter.java** -->
JwtRequestFilter is for filtering and validation of incoming http requests that contains JWT token.
Purpose
1.Intercepting Requests:
The JwtRequestFilter acts as a custom filter that intercepts incoming HTTP requests. It checks if the request contains a valid JWT token in the Authorization header.
2.Validating JWT Tokens:
The filter extracts the JWT token from the **getJwtFromRequest** method
typically formatted as Bearer <token>.



