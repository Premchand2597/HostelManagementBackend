#Oauth2 client configuration
		#Google
		
spring.security.oauth2.client.registration.google.client-id=GOOGLE_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=GOOGLE_CLIENT_SECRET
spring.security.oauth2.client.registration.google.scope=openid, profile, email

		#GITHUB
		
spring.security.oauth2.client.registration.github.client-id=GITHUB_CLIENT_ID
spring.security.oauth2.client.registration.github.client-secret=GITHUB_CLIENT_SECRET
spring.security.oauth2.client.registration.github.scope=user:email, read:user