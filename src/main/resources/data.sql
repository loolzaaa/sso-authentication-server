INSERT INTO USERS (login, salt, config, name, enabled)
    VALUES (
        'admin',
        '1fca962b736b85bb727e9675ab1caf301d4f9b06b5c7585ac95dc7ce0b2349',
        '{"passport":{"credentials_exp": 2524608000000,"roles":["ROLE_ADMIN"]},"example":{"roles":["ROLE_ADMIN"],"privileges":["privilege1"], "someSetting":true}}',
        'admin_name',
        true
);

INSERT INTO HASHES VALUES ('5ac38d6a76b031e4d42459fd311cd0ef08bb0be92099aaf71f8472c6ccbefd8dd24bc315980345845f98912f50719f48ed6078c5a5efd4e83dc67ed16aed9b');
