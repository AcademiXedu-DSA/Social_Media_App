# Social_Media_App

**Setting up the DataBase**
1.we should add h2 db dependencies in pom.xml and we should configure db in application.properties in resources
2.The User table will store information about each user in User.java.
3.Table contains -->username which should be unique 
4.password (String): Stores the hashed password (using Bcrypt for security).
5.role (String): Stores the role of the user, such as "USER", "ADMIN", etc.

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

