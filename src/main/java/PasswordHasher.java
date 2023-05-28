import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Created at 28.05.2023 by Dan.
 */
@SuppressWarnings("all")
public class PasswordHasher {
    private static final int ITERATIONS = 1000;
    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 64 * 8;
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA1";

    public static String generateStrongPasswordHash(String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        char[] chars = password.toCharArray();
        byte[] salt = getSalt();
        PBEKeySpec spec = new PBEKeySpec(chars, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return ITERATIONS + ":" + toHex(salt) + ":" + toHex(hash);
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[SALT_LENGTH];
        sr.nextBytes(salt);
        return salt;
    }

    private static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }
}