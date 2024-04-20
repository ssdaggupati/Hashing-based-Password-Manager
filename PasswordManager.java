import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class PasswordManager {
    private static final int SALT_LENGTH = 16;

    // Generate a random salt
    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }

    // Hash the password using SHA-256 and salt
    public static String hashPassword(String password) {
        try {
            byte[] salt = generateSalt();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashedPassword = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashedPassword) + ":" + Base64.getEncoder().encodeToString(salt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Verify if the entered password matches the hashed password
    public static boolean verifyPassword(String enteredPassword, String hashedPassword) {
        try {
            String[] parts = hashedPassword.split(":");
            byte[] decodedHash = Base64.getDecoder().decode(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashedEnteredPassword = md.digest(enteredPassword.getBytes());
            return MessageDigest.isEqual(decodedHash, hashedEnteredPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }

    // Main method for testing
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Prompt the user for a password
        System.out.print("Enter your password: ");
        String password = scanner.nextLine();

        // Hash the password
        String hashedPassword = hashPassword(password);
        System.out.println("Hashed password: " + hashedPassword);

        // Prompt the user to re-enter the password for verification
        System.out.print("Re-enter your password to verify: ");
        String reEnteredPassword = scanner.nextLine();

        // Verify the password
        boolean isMatch = verifyPassword(reEnteredPassword, hashedPassword);
        System.out.println("Password match: " + isMatch);

        scanner.close();
    }
    /*
     * Test Case:
     * Input:
     * Enter your password: 12345
     * Hashed password: iA7XKmrMrs6nnOPfjkvx0KkoAi70D/k4A/HpnSmKcx4=:7NKkpwSNknb6vFKoOuLMEg==
     * Re-enter your password to verify: 7894
     * 
     * Output:
     * Password match: false
     */

}
