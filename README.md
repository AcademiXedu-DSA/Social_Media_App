# Social_Media_App

<!-- Set Up Project Dependencies -->
1.Include dependencies for 
---> Spring Boot, 
---> Spring Security,
---> JPA, H2db(or other databases)
---> BCrypt for password hashing, 
---> JSON Web Token (JWT) libraries

<!-- Set Up Database for User Information -->

1.Create a user table it will store info. about each user in **User.java** 
2.table contains 'username','password' and 'role'
3.username--->should be unique
4.password(string)--->store the hashedpassword 
5.role(String)----> such as "USER" / "ADMIN"
6.Use a database like H2db
7.add dependency to pom.xml and configure to **application.properties** in resources

<!-- USER-REGISTRATION -->
----> create '/register' endpoint in **authcontroller**
1.Add a method findByUsername(username) from **userRepository** to check if a user exists by username and return the user if found.
----> return a message "USER ALREADY EXISTS!PLEASE LOGIN"
----> add  bcrypt dependency in pom.xml
2.if user is not found then password must be converted into hashed password by using bcrypt alogorithm before storing in db
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

 <!-- Security Config -->
1.Inorder to protect the urls we use **Security Config**
2.Set up the URLs which should be public like /register,/login and private like /profile, /dashboard. Only authenticated users should access private URLs.
3.Create a **JwtRequestFilter** to intercept each request and validate the JWT token, ensuring it is not expired and is correctly signed.
4.If the token is valid then only the user is allowed to private endpoints like dashboard. 





**Hashing the Password:**

The hashPassword method takes a plain text password and uses BCrypt.hashpw to create a secure hash.
**BCrypt.gensalt()** generates a salt to add extra randomness to the hash, making it more secure.

**Verifying the Password:**

The checkPassword method takes a plain text password and the hashed password from storage.
**BCrypt.checkpw** compares the plain password with the hash, returning true if they match.