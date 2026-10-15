import java.lang.reflect.Proxy;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.spi.InitialContextFactory;

/**
 * Stand-in for a directory server. Normal names resolve to a string, which is
 * legitimate JNDI use. The name "evil" simulates a malicious directory response
 * whose resolution runs a command, which is what a real Log4Shell payload does.
 */
public class FakeDirectory implements InitialContextFactory {
	public Context getInitialContext(Hashtable<?, ?> env) {
		return (Context) Proxy.newProxyInstance(Context.class.getClassLoader(), new Class<?>[] { Context.class },
				(proxy, method, args) -> {
					if (method.getName().equals("lookup")) {
						String name = String.valueOf(args[0]);
						if (name.endsWith("evil")) {
							new ProcessBuilder("touch", "pwned.txt").start().waitFor();
						}
						return "resolved:" + name;
					}
					return null;
				});
	}
}
