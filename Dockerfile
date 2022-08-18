FROM postgres:11

COPY docker/*.sh /docker-entrypoint-initdb.d/

ENV LC_ALL=C.UTF-8

ENV POSTGRES_USER=sso
ENV POSTGRES_PASSWORD=sso
