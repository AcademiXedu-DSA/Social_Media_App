# Social_Media_App
File Names:
Model: User.java
Repository: UserRepository.java
Service: AuthService.java
         SessioinManager.java
         AuthApplication.java
Controller: AuthController.java
Security: JwtRequestFilter.java
          JwtUtil.java
          SecurityConfig.java

Psuedocode:

1.User Registration
1.Check if the username already exists. If it does, throw an error.
2.Assign the role of "USER" to the user by default if no specific role is provided.
3.Use PasswordEncoder to encrypt the user's password.
4.Save the user in the database through UserRepository.
5.Generate a JWT for the user via jwtUtil.
6.Establish a session for the user in SessionManager, linking the username with the generated token.
7.Return a success response that includes the token, username, and assigned role.

2.User login
Check User Existence:
1.Look up the username in the UserRepository (database) to see if the user is registered.
2.If the username is not found, throw an AuthenticationException with an appropriate error message.

Validate Password:
1.Use PasswordEncoder to compare the provided inputPassword with the stored, encrypted password for the user.
2.If the password doesn’t match, throw an AuthenticationException.

3.Generate JWT:
1.Use jwtUtil to create a JWT token associated with the username. This token will serve as the user's authentication token.

4.Create User Session:
1.Add a new session in SessionManager, linking the username to the generated token. This session will help manage the user's login state.

5.Return Success Response:
Return a response indicating successful login, along with the token, username, and the user's role. This information can be used by the client for authenticated requests.

3.Logout:

1.Validate JWT Token:
1.Use jwtUtil to check if the token is valid for the given username.
2.If the token is invalid or expired, throw an AuthenticationException.

2.Check Active Session:
1.Verify if there is an active session for the user in SessionManager using the username and token.
2.If no session is found, throw a SessionException indicating no active session.

3.Invalidate Session:
1.If an active session is found, remove or invalidate it in SessionManager to log out the user.

4.Return Success Response:
1.Return a response confirming a successful logout, including the username for reference.
