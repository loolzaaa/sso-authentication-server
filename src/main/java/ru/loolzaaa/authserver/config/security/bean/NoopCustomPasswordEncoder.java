package ru.loolzaaa.authserver.config.security.bean;

public class NoopCustomPasswordEncoder extends CustomPBKDF2PasswordEncoder {
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return true;
    }
}
