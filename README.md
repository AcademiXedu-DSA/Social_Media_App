# Social_Media_App

**Dependencies for Project Setup**
--->spring boot
--->spring security
--->JPA,H2 db
--->Bcrypt 
--->JWT Libraries

**Setting up the DataBase**
1.we should add h2 db dependencies in pom.xml and we should configure db in application.properties in resources
**User.java**
1.The User table will store information about each user in User.java.
2.Table contains -->username which should be unique 
3.password (String): Stores the hashed password (using Bcrypt for security).
4.role (String): Stores the role of the user, such as "USER", "ADMIN".

**UserRepository.java**
The UserRepository interacts with the database, checking for existing users using **findbyUsername** .

**AuthController.java**
Controller will handle the endpoints for user registration **/register**,user login **/login**,user logout **/logout**


**USER REGISTRATION**
1.Create a /register endpoint in AuthController to handle user registration requests.
2.Now AuthController is connected to AuthService and it is connected to UserRepository and checks if the user is already present in db or not. If present it should return "USER ALREADY EXISTS! PLEASE LOGIN"
3.If user is not present in db then plain password entered by user must be converted into hashed password by using Bcrypt algorithm (bcrypt dependency must be added in pom.xml )inorder to avoid brute force attacks 
4.The hashed password and user name must be stored in database and it should return "USER REGISTERED SUCCESFULLY".

**USER LOGIN**
1.Create a /login endpoint in AuthController to handle user login requests.
2.Now Auth Controller calls the authenicateUser method in Auth Service .now the plain password entered by user must be hashed by Bcrypt algorithm inorder to check with encrypted password in Database if both are same then "USER LOGIN SUCCESSFULLY"
3.If not throw an error stating "INVALID CREDENTIALS".
**If user login successfully we should generate a JWT token from JwtUtil.java using HS256 ALGORITHM**
4.Jwt token along with username should be stored in SessionManager using HASH MAP Data structure

**USER LOGOUT**
1.Create a /logout endpoint in AuthController to handle user logout requests.
2.AuthController calls the logout method in AuthService.
3.Check if the session exists in SessionManager (using the username or JWT token to find the entry).
4.If a session is found for the user, remove it from SessionManager.
Return a message like "USER LOGGED OUT SUCCESSFULLY".

**Security Config**
1.Inorder to protect the urls we use Security Config
2.Set up the URLs which should be public like /register,/login and private like /profile, /dashboard. Only authenticated users should access private URLs.
3.Create a JwtRequestFilter to intercept each request and validate the JWT token, ensuring it is not expired and is correctly signed.
4.If the token is valid then only the user is allowed to private endpoints like dashboard.

**JwtUtil.java**
Add jjwt dependency in pom.xml
1. Jwtutil is to manage creation ,validation,extraction of json web tokens
2. It contains a security key that is used by the server to sign and verify the JWT token.
3. It contains methods like
generateToken-used to generate JWT token after succesfull login of user This token can then be sent to the client, who stores it (e.g., in local storage or cookies) for use in future requests.
isTokenValid-Every time a client make request to a protected endpoint, the client sends the JWT along with the request.
4. JwtUtil verifies the token to ensure it hasn’t been tampered with, and it checks if the token is still valid (i.e., hasn’t expired).

**SessionManager.java**
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

**JwtRequestFilter.java**
JwtRequestFilter is for filtering and validation of incoming http requests that contains JWT token.
Purpose
1.Intercepting Requests:
The JwtRequestFilter acts as a custom filter that intercepts incoming HTTP requests. It checks if the request contains a valid JWT token in the Authorization header.
2.Validating JWT Tokens:
The filter extracts the JWT token from the **getJwtFromRequest** method
typically formatted as Bearer <token>.
It then validates the token by using the JwtUtil class
