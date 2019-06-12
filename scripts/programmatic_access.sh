#!/bin/bash
# Create a new OAUTH2 provider DISTINCT from your pomerium configuration
# Select type as "OTHER"
CLIENT_ID='REPLACE-ME.apps.googleusercontent.com'
CLIENT_SECRET='REPLACE-ME'
SIGNIN_URL='https://accounts.google.com/o/oauth2/v2/auth?client_id='$CLIENT_ID'&response_type=code&scope=openid%20email&access_type=offline&redirect_uri=urn:ietf:wg:oauth:2.0:oob'

# This would be your pomerium client id
POMERIUM_CLIENT_ID='REPLACE-ME.apps.googleusercontent.com'

echo "Follow the following URL to get an offline auth code from your IdP"
echo $SIGNIN_URL

read -p 'Enter the authorization code as a result of logging in: ' CODE
echo $CODE

echo "Exchange our authorization code to get a refresh_token"
echo "refresh_tokens can be used to generate indefinite access tokens / id_tokens"
curl \
	-d client_id=$CLIENT_ID \
	-d client_secret=$CLIENT_SECRET \
	-d code=$CODE \
	-d redirect_uri=urn:ietf:wg:oauth:2.0:oob \
	-d grant_type=authorization_code \
	https://www.googleapis.com/oauth2/v4/token

read -p 'Enter the refresh token result:' REFRESH_TOKEN
echo $REFRESH_TOKEN

echo "Use our refresh_token to create a new id_token with an audience of pomerium's oauth client"
curl \
	-d client_id=$CLIENT_ID \
	-d client_secret=$CLIENT_SECRET \
	-d refresh_token=$REFRESH_TOKEN \
	-d grant_type=refresh_token \
	-d audience=$POMERIUM_CLIENT_ID \
	https://www.googleapis.com/oauth2/v4/token

echo "now we have an id_token with an audience that matches that of our pomerium app"
read -p 'Enter the resulting id_token:' ID_TOKEN
echo $ID_TOKEN

curl -X POST \
	-d id_token=$ID_TOKEN \
	https://authenticate.corp.beyondperimeter.com/api/v1/token

read -p 'Enter the resulting Token:' POMERIUM_ACCESS_TOKEN
echo $POMERIUM_ACCESS_TOKEN

echo "we have our bearer token that can be used with pomerium now"
curl \
	-H "Authorization: Bearer ${POMERIUM_ACCESS_TOKEN}" \
	"https://httpbin.corp.beyondperimeter.com/"
