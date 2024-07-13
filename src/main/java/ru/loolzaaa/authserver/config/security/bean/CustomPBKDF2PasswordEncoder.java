package ru.loolzaaa.authserver.config.security.bean;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class CustomPBKDF2PasswordEncoder implements PasswordEncoder {

    private final Log logger = LogFactory.getLog(this.getClass());

    private static final int ITERATIONS = 1000;

    private static final String LOCAL_PARAM = "0CE2C3B9373A978CDB5D71D404FD867B75B358D7C5F6EC5AB8D95D3295CDC005";

    private String salt;

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        } else {
            return hashPassword(rawPassword.toString(), salt);
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        } else if (encodedPassword != null && !encodedPassword.isEmpty()) {
            return checkPassword(rawPassword.toString(), encodedPassword);
        } else {
            this.logger.warn("Empty encoded password");
            return false;
        }
    }

    private String hashPassword(String password, String salt) {
        char[] passChars = password.toCharArray();
        byte[] saltChars = fromHex((salt == null ? "" : salt) + LOCAL_PARAM);

        try {
            PBEKeySpec spec = new PBEKeySpec(passChars, saltChars, ITERATIONS, 63 * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return toHex(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private boolean checkPassword(String plaintext, String storedHash) {
        String originalHash = hashPassword(plaintext, salt);

        byte[] hash = fromHex(storedHash);
        byte[] testHash = fromHex(originalHash);

        int diff = hash.length ^ testHash.length;
        for (int i = 0; i < hash.length && i < testHash.length; i++) {
            diff |= hash[i] ^ testHash[i];
        }
        return diff == 0;
    }

    public String generateSalt() {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] saltByteArr = new byte[31];
            sr.nextBytes(saltByteArr);
            return toHex(saltByteArr);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return Strings.repeat("0", paddingLength) + hex;
        } else {
            return hex;
        }
    }

    private byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
