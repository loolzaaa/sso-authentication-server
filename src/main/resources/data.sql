INSERT INTO USERS (login, salt, config, enabled)
    VALUES (
        'admin',
        '1fca962b736b85bb727e9675ab1caf301d4f9b06b5c7585ac95dc7ce0b2349',
        '{"passport":{"credentials_exp": 2524608000000,"roles":["ROLE_ADMIN"]},"example":{"roles":["ROLE_ADMIN"],"privileges":["privilege1"], "someSetting":true}}',
        true
    ),
    (
        'user',
        'f735f1e6322ad9319abe78bc02ac06f8ad7a8673a81eb33a8525c0ff359fc8',
        '{"passport":{"credentials_exp": 2524608000000}}',
        true
    ),
    (
        'temp',
        'c02cbc396175f111aec73368be4957a0c2fad8f3dde7a70256d41d9a31e4b4',
        '{"passport":{"credentials_exp": 2524608000000, "temporary":{"dateFrom": "2023-01-01", "dateTo": "2030-01-01", "originTabNumber": "user", "pass": "pass"}}}',
        true
    );

INSERT INTO HASHES VALUES
    ('5ac38d6a76b031e4d42459fd311cd0ef08bb0be92099aaf71f8472c6ccbefd8dd24bc315980345845f98912f50719f48ed6078c5a5efd4e83dc67ed16aed9b'),
    ('21a2a7ef7b6979be41b9d6872942bf6df2daf1f8fd547cc9da729b84c47442209948e96786a9a66a9983b0b032d119c6e6f34bc222c1ebf0bd36fbfc0e0790'),
    ('ba45d53cc80da0c8a3b08d73425747d389bd26b115aef1d38728bc8e9b5c5e973c0aeba8edf04b73d05fb220bc8b67138f1e1ad4cc3e865867f0e1ff1e7745');
