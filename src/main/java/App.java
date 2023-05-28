import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Created at 28.05.2023 by Dan.
 */
public class App {

    public static void main(String[] args) {
        try {
            String originalPassword = "mkjerhwuvfg5449785932-=!";
            String generatedSecuredPasswordHash = PasswordHasher.generateStrongPasswordHash(originalPassword);
            System.out.println("Generated Password Hash: " + generatedSecuredPasswordHash);

            boolean matched = PasswordValidator.validatePassword("mkjerhwuvfg5449785932-=!", generatedSecuredPasswordHash);
            System.out.println("Password Matches: " + matched);

            matched = PasswordValidator.validatePassword("trjhtrjryj6576ytrru-..../", generatedSecuredPasswordHash);
            System.out.println("Password Matches: " + matched);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }
}
