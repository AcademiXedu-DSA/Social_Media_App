**Files We Are Used**
"AuthController.java"
"AuthService.java"
"Sessionmanager.java"
"User.java"
"UserRepository.java"
"jwtRewuestFilter.java"
"JwtUtil.java"
"securityConfig.java"

**USER REGISTRATION**
1.First User Comes and hit the Register endpoint(/Auth/regitser) By Entering Details User is Registered
2.If User is Available it will Throw an error user already exist.user is not available it will register 
2.In the Registering User Will Enter a Password For Security Purpose We Will Hash The Password By using Bcrypt Algorithm
3.Registration Details Will be Stored in DataBase User.Java
4.After registration is Successful it returns message "User registered successfully"

**USER LOGIN**
1.User will login By hitting the endpoint (/Auth/Login) with username and password
2.It checks And compare  the ActualPassword with BcryptedPassword if both are Match User is able to Login
3.After Login the JWtUtil will generate Token to manage the Sessions.
4.The Generated Token Will be Stored in SessionManager.java for Session Tracking 
5.The Token Will be Stored in Sessionmanager.java Along with Username To Manage Sessions
6.We are Storing the Token And username in Hashmap for each user can have only one active token  at a time 
  HashMap is Used For It is Best Choice For Token retrieving very Fast because it has Time Complexity O(1)
7.If the  User will Not exists it Shows an error Used Not Found

**User Logout**
1.User will Hit the logout endPoint(/Auth/Logout)
2.retrives the Authorization header used to pass the user credentials 
3.Check the  session which  exists in SessionManager (using  username or JWT token).
3.Check that is not null and starts with "Bearer"
4.Use jwtUtil to extract the username associated with the token.
5.Call the logout method in authService, passing the username.
6.If successful, return an OK response with the message "Logged out successfully".
7.it will delete the token Also.

**JwtRequestFilter**

1.Retrieve the Authorization header from the HTTP request.
2.If header is valid (starts with "Bearer "), extract the JWT token.
3.Try to extract the username from the JWT token.
4.Check if username is not null
5.If true, validate the session using SessionManager.
6.If session is valid Create UserDetails object with username.
7.Validate the JWT token.
8.If token is valid Create authentication token with UserDetails.Set the authentication in SecurityContext.
9.Pass the request and response to the next filter in the chain.

**JwtUtil**
The JwtUtil Will do this Actions
1.Extract Username from token 
2.Extract Expiration Date from token 
3.Retrieve a Specific Claim from the token
4.Retrieve All Claims from the token with SECRET_KEY and return the claims
5.Checks the Token Expiration
6.Generate a New Token for a User
7.Create Token 
8.Validate the Token
  
**SecurityConfig**
1.Disable CSRF it  defends against requests made using the user's session without their knowledge.
    Set CORS configuration it esures that only trusted domains can interact with your resources.
    Set stateless session management
    Allow unauthenticated access to "/auth/**" and "/h2-console/**"
    Require authentication for all other requests
    Add JwtRequestFilter before UsernamePasswordAuthenticationFilter
    Allow H2 console
2.passwordEncoder for managing the Bcrypt to hash the password 
3.Allow CORS from "http://localhost:3000"
     it Enable specific methods and headers
     it Allow credentials
