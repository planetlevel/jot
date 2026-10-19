package org.openolly;

import java.util.List;

/**
 * Tells when a call was made by the platform doing work nothing in the application asked for, which sensors leave out.
 * Loading a class opens jars to check their signatures, and compiling a page reads and parses source. Hashing, file
 * and URL calls along the way aren't the application's, and in a servlet container they happen in the middle of
 * requests, so a scope can't tell them from the application's own.
 *
 * A call is the platform's when walking out from it, through nothing but JDK and server frames, reaches a class loader
 * or the page compiler. Code that is the application's or a library's, closer in than that, like a class initializer,
 * still counts. So does work the application asked for, like a page fetching an https address, because the platform's
 * frames then lead out to the page and never reach a class loader.
 *
 * What counts as work is the ignore list in the jots file, which the dashboard reads as well, so both leave out the same
 * calls. Without one the list below is used. It is not the same as saying which code is the platform, that is built in
 * and is only JDK and server packages. An entry is a package, a class or a class and method, and matches itself and
 * everything inside it, so java.lang.ClassLoader covers every method of it and of its inner classes.
 *
 * The dashboard's classify in dashboard/store.py is the same test, for events from agents that didn't leave them out.
 *
 * Only sensors that observe use it. A rule keeps seeing everything, since a request that has a class loader fetch
 * code from a URL it chose also looks like this, and that is something a rule should be able to stop.
 */
public final class PlatformWork {

	private static final String[] PLATFORM = { "java.", "javax.", "jdk.", "sun.", "com.sun.", "jakarta.", "org.w3c.", "org.xml.",
			"org.ietf.", "org.apache.catalina.", "org.apache.coyote.", "org.apache.tomcat.", "org.apache.jasper.", "org.apache.el.",
			"org.apache.naming.", "org.eclipse.jdt.", "org.openolly." };

	/** What is ignored when the jots file doesn't say. */
	public static final List<String> DEFAULT_IGNORE = List.of( "java.lang.ClassLoader", "java.net.URLClassLoader", "jdk.internal.loader",
			"org.apache.catalina.loader", "org.apache.jasper.compiler", "org.apache.jasper.JspCompilationContext.compile", "org.eclipse.jdt" );

	private static volatile List<String> work = DEFAULT_IGNORE;

	private PlatformWork() {}

	/** Sets the ignore list, from the jots file. Null goes back to the default and an empty list ignores nothing. */
	public static void configure(List<String> entries) {
		work = entries == null ? DEFAULT_IGNORE : List.copyOf( entries );
	}

	public static List<String> ignored() {
		return work;
	}

	/** True if the call at the start of this stack was made by class loading or page compiling and nothing the application did. */
	public static boolean inside(StackTraceElement[] stack) {
		if ( stack == null ) return false;
		for ( int position = 0; position < stack.length; position++ ) {
			String clazz = stack[position].getClassName();
			if ( !startsWithAny( clazz, PLATFORM ) ) return false;      // application or library code comes first
			// the call being watched is not the work itself, an application can call it
			if ( position > 0 && isWork( clazz + "." + stack[position].getMethodName() ) ) return true;
		}
		return false;
	}

	private static boolean isWork(String name) {
		for ( String entry : work ) {
			if ( name.equals( entry ) || name.startsWith( entry + "." ) || name.startsWith( entry + "$" ) ) return true;
		}
		return false;
	}

	private static boolean startsWithAny(String text, String[] prefixes) {
		for ( String prefix : prefixes ) {
			if ( text.startsWith( prefix ) ) return true;
		}
		return false;
	}
}
