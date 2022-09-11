package ru.loolzaaa.authserver.config.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CookieName {
    ACCESS("_t_access"),
    REFRESH("_t_refresh"),
    RFID("_t_rfid");

    private final String name;
}
