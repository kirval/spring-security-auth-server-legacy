1. Run Redis instance from ```docker-compose``` file.
2. Run Authorization and Resource servers.
3. Retrieve Access Token:
   ```
   curl --location --request POST 'http://localhost:9000/oauth/token' 
   --header 'content-type: application/x-www-form-urlencoded' 
   --data-urlencode 'username=user' 
   --data-urlencode 'password=password' 
   --data-urlencode 'grant_type=password' 
   --data-urlencode 'client_id=client' 
   --data-urlencode 'client_secret=secret'
   ```
4. Get access token from p.3 response and use it to retrieve resource:
   ```
   curl --location --request GET 'http://localhost:9001/test' 
   --header 'Authorization: Bearer {access_token}'
   ```