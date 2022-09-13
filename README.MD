# Single Sign-On authentication server

This Single Sign-On (SSO) is server based on Spring Security. The main authentication routine happens through a standard login form. Further authentication occurs through Json Web Tokens (JWT) tokens, which are checked through a custom filter. In addition, there are a number of APIs that are accessed through Basic authentication with predefined users in the application configuration. All other components of the system are based on standard Spring Security beans with minor changes.

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
> ./mvnw clean install -DskipTests
> cd ./target/
> java "-Dspring.profiles.active=dev,postgres" -jar .\auth-server-0.2.0.jar
```

# Server Configuration

Under construction
