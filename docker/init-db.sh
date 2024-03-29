#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE TABLE IF NOT EXISTS users
    (
        id integer NOT NULL GENERATED BY DEFAULT AS IDENTITY,
        login text NOT NULL,
        salt text NOT NULL DEFAULT 'SERVICE',
        config jsonb NOT NULL,
        name text NOT NULL DEFAULT 'SERVICE',
        enabled boolean NOT NULL DEFAULT false,
        CONSTRAINT users_pkey PRIMARY KEY (id),
        CONSTRAINT users_login_key UNIQUE (login)
    );

    CREATE TABLE IF NOT EXISTS refresh_sessions
    (
        user_id integer NOT NULL,
        refresh_token uuid NOT NULL,
        fingerprint text NOT NULL,
        expires_in timestamp with time zone NOT NULL,
        CONSTRAINT refresh_sessions_pkey PRIMARY KEY (refresh_token),
        CONSTRAINT refresh_sessions_user_id_fkey FOREIGN KEY (user_id)
            REFERENCES users (id) MATCH SIMPLE
            ON UPDATE NO ACTION
            ON DELETE NO ACTION
            NOT VALID
    );

    CREATE TABLE IF NOT EXISTS hashes
    (
        hash text NOT NULL
    );

    CREATE TABLE IF NOT EXISTS webhooks
    (
        id text NOT NULL,
        event text NOT NULL,
        secret text NOT NULL,
        url text NOT NULL,
        enabled boolean NOT NULL,
        CONSTRAINT webhooks_pkey PRIMARY KEY (id)
    );

    INSERT INTO users (login, salt, config, enabled)
        VALUES
            ('admin', '1fca962b736b85bb727e9675ab1caf301d4f9b06b5c7585ac95dc7ce0b2349', '{
                "passport": {
                    "roles": [
                        "ROLE_ADMIN"
                    ],
                    "credentials_exp": 2524608000000
                },
                "example": {
                    "roles": [
                        "ROLE_ADMIN"
                    ],
                    "privileges": [
                        "privilege1"
                    ],
                    "someSetting":true
                }
            }', true),
            ('user', 'f735f1e6322ad9319abe78bc02ac06f8ad7a8673a81eb33a8525c0ff359fc8', '{
                "passport": {
                    "credentials_exp": 2524608000000
                }
            }', true);

    INSERT INTO hashes VALUES
      ('5ac38d6a76b031e4d42459fd311cd0ef08bb0be92099aaf71f8472c6ccbefd8dd24bc315980345845f98912f50719f48ed6078c5a5efd4e83dc67ed16aed9b'),
      ('21a2a7ef7b6979be41b9d6872942bf6df2daf1f8fd547cc9da729b84c47442209948e96786a9a66a9983b0b032d119c6e6f34bc222c1ebf0bd36fbfc0e0790');

    INSERT INTO WEBHOOKS (id, event, secret, url, enabled)
        VALUES (
            'TEST_WEBHOOK_ID',
            'DELETE_USER',
            '12345678',
            'http://localhost:8888/example',
            true
        );
EOSQL
