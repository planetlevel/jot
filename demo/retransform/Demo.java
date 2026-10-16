import java.io.File;
import java.security.MessageDigest;

/** Calls two JDK classes the JVM loads before any agent starts, and two it loads later. */
public class Demo {
    public static void main(String[] args) throws Exception {
        new File("/var/data/report.txt");            // loaded at JVM start
        MessageDigest.getInstance("MD5");             // loaded at JVM start
        new ProcessBuilder("true");                   // loaded when first used
        javax.crypto.Cipher.getInstance("AES");       // loaded when first used
    }
}
