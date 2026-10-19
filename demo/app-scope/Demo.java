import java.io.File;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.MessageDigest;

/**
 * A program with no servlet, where the application starts at a method carrying an annotation, the way a framework calls an
 * @Tool, a listener or a scheduled job. File and MessageDigest calls are made before, inside and after it.
 */
public class Demo {

	@Retention(RetentionPolicy.RUNTIME)
	@interface Entry { }

	@Entry
	static void handle(String what) throws Exception {
		new File( "inside/" + what );
		MessageDigest.getInstance( "SHA-256" );
		helper();
	}

	static void helper() {
		new File( "inside/helper" );
	}

	public static void main(String[] args) throws Exception {
		new File( "outside/startup" );
		MessageDigest.getInstance( "MD5" );
		handle( "one" );
		handle( "two" );
		new File( "outside/after" );
	}
}
