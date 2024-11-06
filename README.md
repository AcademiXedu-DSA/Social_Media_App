# Social_Media_App
->Entity File
.Create a folder as Model and Create a users file
.In the users java file insert create a table as users(@Entity)
.In the table users create entity as ID as primer key (@ID)
.Create two entity as Username and password.(username,pass)
.Make a Validate username as Email by using pattern.(@Patter)
.And by using Validation make sure to the entity should not Null(@NotNull)

->Repository Layer
.create a interface and extend the jpa repo
.Include the jparepository (<user,Long>)
.Querys H2 for fetaching the user and pass.

->security:
(Jwt RequestFilter)
.create a JwtRequestFilter to filter the tokens.
.it use to validate the incoming requests by using JWt token.
.Extract the username from the jwt token
.validate the JWT token .
.check the jwt token is expired or altered.
.handle the exception if invalid token occurs.

(JWTUtil)
.In this we need to check the token is created or not and keep a expire for the token
.retrieve the token and extract the expiration date from the token.
.check the token has expired.
.validate the token by checking its claims and exporation.
.Generate a new JWT token based on the username .
(SecurityConfig)
.checking the api end points(allowing only the permitted api).
taking the custom jwt filter that check token.
.service for loading user details.
.utility class for Jwt token operations.
.making to use only authentication by antMatchers().
.handle the unauthorized requests.
.handle unauthorized access.
      
->service:
(AuthService)
.Creating and validating the JWt.
.Authenticate the users wit the credentials.
.Generate the JWT token for the authenticated user.
.Making the credentials encrypted by using bcryptpasswordEncoder().
.Verify the user data.

(Session Manager)
.store the session token.(HashMap)
.update the session based on the logins.
.make a cache to store the recent sessions.
.Give a session timing and check the session is updated.
.manage the session wen the user logout.

->Controller:
(AuthController)
.keep a restcontroller and create requestmapping end point(/api/).
.use postmap and request the user data.
.validate the user by using a request.
.login request api to login.
.logout request api for logout.


->Application properties :
.Configuration of H2 database
.Configurating the Security 
.Configurating the port.



