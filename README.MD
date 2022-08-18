docker build --tag sso-postgres .

docker run -dp 9898:5432 --rm --name sso-postgres sso-postgres

docker exec -it sso-postgres /bin/bash