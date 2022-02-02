# kotlin-spring-oauth2-authorization-server
* references
    * https://docs.github.com/en/free-pro-team@latest/developers/apps/creating-an-oauth-app
    * https://rieckpil.de/test-spring-webclient-with-mockwebserver-from-okhttp/
    * https://www.manning.com/books/spring-security-in-action
    * https://stackoverflow.com/questions/49215866/what-is-difference-between-private-and-public-claims-on-jwt
    * https://idea-instructions.com/public-key/
    * https://medium.com/@jad.karaki/identity-management-saml-vs-oauth2-vs-openid-connect-c9a06548b4c5
    * https://hackernoon.com/demystifying-oauth-2-0-and-openid-connect-and-saml-12aa4cf9fdba
    * https://sectigostore.com/blog/5-differences-between-symmetric-vs-asymmetric-encryption
    * https://portswigger.net/web-security/csrf
    * https://www.keycdn.com/blog/difference-between-http-and-https
    * https://www.cloudflare.com/learning/ssl/why-is-http-not-secure/
    * https://www.geeksforgeeks.org/rsa-algorithm-cryptography
    * https://www.checkmarx.com/knowledge/knowledgebase/session-fixation
    * https://portswigger.net/web-security/cross-site-scripting
    * https://www.ptsecurity.com/ww-en/analytics/knowledge-base/how-to-prevent-sql-injection-attacks/
    * [Session Fixation - how to hijack a website using session fixation method](https://www.youtube.com/watch?v=eUbtW0Z0W1g)
    * [SSL/TLS for Mortals by Maarten Mulders](https://www.youtube.com/watch?v=yJrJEvvW_HA)
    * [The Hacker's Guide to JWT Security by Patrycja Wegrzynowicz](https://www.youtube.com/watch?v=dq39w4MiZzs)
    * [GOTO 2020 • OAuth and OpenID Connect in Plain English • Nate Barbettini](https://www.youtube.com/watch?v=sSy5-3IkXHE)
    * [2019 - Grzegorz Krol - Uwierzytelnienie oraz Autoryzacja w Świecie Mediów i Dostawców Tożsamości](https://www.youtube.com/watch?v=HJhbAxtqFnk)
    * https://jwt.io/introduction/

## general
* authentication
    * process leading to identification
* authorization
    * leading to grant access
* http vs https
    * HTTP sends data over port 80 while HTTPS uses port 443
    * HTTPS uses TLS (SSL) to encrypt normal HTTP requests and responses
* encoding vs encrypting vs hashing
    * encoding
        * any transformation of a given input
        * function: `x -> y`
    * encryption
        * type of encoding
            * to obtain the output: input + key
        * function: `(x, publicKey) -> y`
        * decryption: `(y, privateKey) -> x`
        * symmetric key: `publicKey == privateKey`
        * asymmetric keys: two different keys
    * hashing
        * type of encoding
        * function is only one way (cannot get back the input x)
        * sometimes the hashing function could also use a random value
            * `(x, salt) -> y`
            * salt makes the function stronger

## token
* token ~ access card
    * analogy
        1. when you visit an office building, you first go to the reception desk
        1. you identify yourself (authentication), and you receive an access card (token)
        1. you can use the access card to open some doors, but not necessarily all doors
        1. card is assigned for a certain period (ex. one day)
    * application obtains a token as a result of the authentication process and to access resources
    * application uses them to prove it has authenticated a user
    * tokens can even be regular strings
        * example: UUID
    * steps
        1. X authenticates with his credentials
        1. app generates a token
        1. app returns the token to X
        1. X wants to access his resources
            * client sends the access token in the request
        1. app validates token
        1. if token is valid - return resources
    * advantages
        * help avoiding credentials sharing in all requests
            * more often you expose the credentials, the bigger the chances are that
              someone intercepts them
            * example: HTTP Basic assumes you send credentials for each request
        * could be created with a short lifetime
            * if someone steals the token, he won’t be able to use it forever
                * token might expire before they find out how to use it
        * could be invalidated without invalidating the credentials
            * people tend to have the same credentials for multiple apps
        * could store additional details
            * replaces a server-side session with a client-side session
                * better flexibility for horizontal scaling
            * example: stores user roles
        * delegate authentication responsibility to another component (authorization server)
            * we could implement a system that doesn’t manage its own users
            * allows users to authenticate using credentials from GitHub, Twitter, and so on
            * enhance scalability
            * makes the system architecture more natural to understand and develop
* JSON Web Token (JWT)
    * pronunciation: jot
    * https://jwt.io/
    * typically looks like this: `xxxxx.yyyyy.zzzzz`
    * three parts separated by a dot
        * header
            * formatted as JSON + Base64 encoded
            ```
            { // store metadata related to the token
                "alg": "HS256", // algorithm that generates the signature
                "typ": "JWT" // the type of the token
            }
            ```
        * payload
            * formatted as JSON + Base64 encoded
            ```
            {
                "sub": "1234567890",
                "name": "John Doe",
                "admin": true
            }
            ```
            * contains the claims - statements about user and additional data
                * registered claims
                    * predefined claims which are not mandatory but recommended
                    * example: exp - expiration time
                * public claims
                    * defined for public consumption
                    * required to be collision resistant
                    * should be well documented
                * private claims
                    * known only to the producer and consumer of a JWT
        * signature
            ```
            HMACSHA256( // example with HMAC SHA256 algorithm
                base64UrlEncode(header) + "." +
                base64UrlEncode(payload),
                secret
            )
            ```
            * used to verify the message wasn't changed along the way
            * if signed with a private key, it can also verify the sender of the JWT
            * can be missing
            * when a JWT is signed, we also call it a JWS (JSON Web Token Signed)
                * if a token is encrypted, we also call it a JWE (JSON Web Token Encrypted)
    * keep the token as short as possible
        * if the token is long, it slows the request
        * the longer the token, the more time the cryptographic algorithm needs for signing it

## cryptographic keys
* math
    * the idea of RSA: it is difficult to factorize a large integer
        * public key: (multiplication of two large prime numbers, random number)
        * private key: derived from the same two prime numbers
        * encryption strength totally lies on the key size
            * strength of encryption increases exponentially
    * selecting public & private key
        1. select two prime numbers, `p = 11`, `q = 17`
        1. calculate product (very fast): `p * q = 187`
        1. select random number < product, `e = 3`
        1. find `d` so that `(d * e - 1) mod (p - 1)*(q - 1) = 0`
            * `(d * 3 - 1) mod (10 * 16) = 0`
            * `320 mod 160 = 0` // fill a random number that satisfies the equation
            * `(321 - 1) mod 160 = 0`
            * `107 * 3 = 321 => d = 107`
        * `(p*q, e)` - public key, `d` - private key
    * lets encrypt G (7th letter of alphabet)
        * `p*q = 187`, `e = 3`
        * `7^e = 7^3 = 343` // G ~ 7
        * `343 mod 187 = 156`
    * lets decrypt 156
        * `d = 107`
        * `156^d = 156^107 = ...`
        * `156^107 mod 187 = 7`
* symmetric vs asymmetric
    * symmetric
        * only one key (symmetric key)
        * the same key is used to encrypt and decrypt the message
        * secret key is shared
        * risk of compromise is higher
    * asymmetric
        * two different cryptographic keys (asymmetric keys: public and private) are
          used for encryption and decryption
        * private key is not shared

## oauth2
* delegated authorization
    * how can I allow an app to access my data without necessarily giving it my password?
    * authorization is the ability of an external app to access resources
    * example: Spotify trying to access your facebook friends list to import it into Spotify
* implementations: Keycloak or Okta
* defines four roles:
    * Resource Owner
        * the user himself
    * Client
        * application requesting access to a resource server
    * Authorization Server
        * server issuing access token to the client
        * token will be used for the client to request the resource server
        * stores the user’s and client’s credentials
            * client credentials: allows known applications to be authorized by it
    * Resource Server
        * server hosting protected data
            * example: Facebook hosting your profile and personal information
        * client obtains an access token from the authorization server
            * adds the token to the HTTP request headers (to resource server)
        * three options for implementing token validation at the resource server level
            * resource server directly call the authorization server to verify an issued token
                * remember the rule of thumb: the network is not 100% reliable
            * shared database where the authorization server stores tokens
                * resource server can access and validate the tokens
                * also called blackboarding
                * database might become a bottleneck
            * cryptographic signatures
                * authorization server signs the token when issuing it
                    * resource server validates the signature
                * authorization server uses a private key to sign it
                * resource server uses a public key to verify signature
                * commonly used
                    * google, twitter etc
                        * https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/
* refresh tokens
    * token that doesn’t expire is too powerful
    * to obtain a new access token, the client can rerun the flow
        * not really user friendly
        * example: 20-minute lifespan
            * app would redirect back about three times every hour to log in again
    * used to obtain a new access token instead of reauthentication
        * storing the refresh token is safer: you can revoke it if you find that it was exposed
* vulnerabilities
    * with a user logged in, CSRF is possible if the application doesn’t apply any CSRF protection mechanism
    * token hijacking

## OpenId Connect
* allows for "Federated Authentication"
* are built using the Oauth2.0 and then adding a few additional steps over
* Federated Authentication is a completely different from Delegated Authorization
    * example: Federated Authentication is logging to Spotify using your facebook credentials
    * distinction is important because OAuth 2.0 flow is designed to "grant authorization" and
      is not meant to be used to "authenticate"

## insomnia
* GET: some service url
* tab Auth: OAuth 2.0
    * Grant Type: Authorization Code
    * Authorization URL: http://localhost:8080/oauth/authorize
    * Access Token URL: http://localhost:8080/oauth/token
    * Client Id: client1
    * Client Secret: secret1
