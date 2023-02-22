[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/loolzaaa/sso-authentication-server/branch/master/graph/badge.svg?token=F7H6YNRKST)](https://codecov.io/gh/loolzaaa/sso-authentication-server)

# Single Sign-On authentication server

This Single Sign-On (SSO) is server based on Spring Security. The main authentication routine happens through a standard login form. Further authentication occurs through Json Web Tokens (JWT), which are checked through a custom filter. In addition, there are a number of APIs that are accessed through Basic authentication with predefined users in the application configuration. All other components of the system are based on standard Spring Security beans with minor changes.

# Server Startup

The server consists of two parts:

- Docker container with a database of users and configurations of external applications
- Java application of the server itself.

First, clone this repository and navigate to the project folder:
```shell
> cd ~
> git clone https://github.com/loolzaaa/sso-authentication-server.git
> cd sso-authentication-server
```

## Database container startup

Build Docker image from project folder:
```shell
> docker build --tag sso-postgres .
```

Run Docker container in detached mode with published port `9898` and predefined container name
```shell
> docker run -dp 9898:5432 --rm --name sso-postgres sso-postgres
```
**Note:** *--rm* flag denotes deletion of container after stop. To prevent this behavior from being undesirable, you can create a physical or bind mount volume.

If you want to connect to the container database, you need to run the following command:
```shell
> docker exec -it sso-postgres /bin/bash -c "psql -U sso -d sso"
```
**Note:** the user (*sso* in example) and database name (*sso* in example) for connecting is specified in the application configuration.

If you want to see the logs of a running container, then you need to run the following command:
```shell
> docker logs -f sso-postgres
```
**Note:** this command show logs in *follow* mode.

## Java application startup

Run application with `spring-boot-maven-plugin` and `dev`, and `postgres` profiles active:
```shell
> ./mvnw spring-boot:run -D spring-boot.run.profiles=dev,postgres
```

**OR** you can package application to Uber JAR and run it:
```shell
> ./mvnw clean package -DskipTests
> cd ./target/
> java "-Dspring.profiles.active=dev,postgres" -jar ./auth-server-0.4.0.jar
```

# Server Configuration

Some properties can be defined to prevent other dependencies from changing the required values.
```
# Remove all session tracking attributes from servlet container
server.servlet.session.persistent=false
server.servlet.session.tracking-modes=

# Expose JMX endpoint for RFID key update
spring.jmx.enabled=true
```

## Main configuration

```
# Application name for SSO
# Will be the main authority to access the application!
sso.server.application.name=passport

# Activate flag for RFID authentication through RFID key
# This type of authentication implies access 
# through a SINGLE key, which is insecure!
# Default: false
sso.server.rfid.activate=true

# Login page URI
# Default: /login
sso.server.login-page=/login

# Refresh token URI for browser request
# Default: /trefresh
sso.server.refresh-uri=/trefresh

# SameSite parameter for token cookies
# Default: Lax
sso.server.cookie.same-site=Lax

# JWT TTL parameter
# Default: 30s for access, 10h for refresh
sso.server.jwt.access-ttl=5m
sso.server.jwt.refresh-ttl=10h

# Predefined users for Basic authentication
# Can be used to better restrict access 
# between external applications
sso.server.basic.users[0].username=SERVICE
sso.server.basic.users[0].password=PASSWORD

# Enable Spring Actuator endpoints
# Default: false
sso.server.basic.actuatorEnable=true
```
**Note:** all basic users must have `BasicUsersProperties.basicUserAuthority` authority for access.

### External application logout

In addition, the application defines a user to revoke JWT tokens when external applications logout.  
This properties available under `sso.server.basic.<property-name>`.
```Java
private String revokeUsername = "REVOKE_TOKEN_USER";
private String revokePassword = "REVOKE_TOKEN_USER_PASSWORD";
private String revokeAuthority = "REVOKE_TOKEN";
```

### Actuator endpoint access

Actuator endpoints available (if enable, see server configuration) under Basic Authentication for special user.  
This properties available under `sso.server.basic.<property-name>`.
```Java
private String actuatorUsername = "actuator";
private String actuatorPassword = "1234";
private String actuatorAuthority = "ACTUATOR_ADMIN";
```

## Database User config scheme

The user configuration schema can be viewed on the [wiki page](https://github.com/loolzaaa/sso-authentication-server/wiki/User-definition-schema).

## Secret key generation

Secret key generation process described on the [wiki page](https://github.com/loolzaaa/sso-authentication-server/wiki/JWT-secret-key-generation).  
  
After generation, keys **MUST** have `public.key` and `private.key` names and can be placed in:
- classpath under `resources/keystore/` folder
- somewhere on local path specified by `sso.server.jwt.key-path` property

## Application profiles

The application must be launched with one of two profiles: `dev`, `prod`.  
Optional profile: `noop`, `ssl`.

### Developer mode

Main active profile: `dev`.  
Additional profiles: `h2` **OR** `postgres`. 

Additional profiles determine which database the application will connect to: H2 in-memory database or PostgreSQL database inside Docker container.

### Production mode

Main active profile: `prod`.  
Additional profiles: N/A.

Application properties for production (`application-prod.properties`) mode already contains database connection parameters.

### Password encoder for development

If you run application with optional profile `noop`, then special password encoder will be active.  
It is always match any password for **JWT API request matchers**.

## RFID Authentication

RFID authentication description can be viewed on the [wiki page](https://github.com/loolzaaa/sso-authentication-server/wiki/RFID-Authentication).
