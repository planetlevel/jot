package org.openolly;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

class PlatformWorkTest {

	@AfterEach
	void backToTheDefault() {
		PlatformWork.configure( null );
		AppScope.configure( List.of() );
	}

	private static StackTraceElement f(String clazz, String method) {
		return new StackTraceElement( clazz, method, clazz.substring( clazz.lastIndexOf( '.' ) + 1 ) + ".java", 1 );
	}

	// a hash requested while the JVM checks the signature of a jar, as Tomcat does the first time a class is loaded in a request
	private static final StackTraceElement[] JAR_CHECK = {
		f( "java.security.MessageDigest", "getInstance" ), f( "sun.security.util.ManifestEntryVerifier", "setEntry" ),
		f( "java.util.jar.JarVerifier", "beginEntry" ), f( "jdk.internal.loader.URLClassPath$JarLoader$2", "getBytes" ),
		f( "java.lang.ClassLoader", "defineClass" ), f( "org.apache.catalina.loader.WebappClassLoaderBase", "findClass" ),
		f( "org.apache.jsp.list_jsp", "_jspService" ) };

	@Test
	void classLoadingAndPageCompilingAreTheWorkOfThePlatform() {
		Assertions.assertTrue( PlatformWork.inside( JAR_CHECK ) );
		Assertions.assertTrue( PlatformWork.inside( new StackTraceElement[] { f( "java.io.File", "<init>" ),
			f( "org.apache.jasper.compiler.Compiler", "compile" ), f( "org.apache.jasper.servlet.JspServletWrapper", "service" ) } ) );
	}

	@Test
	void whatTheApplicationOrALibraryDidIsNotTheWork() {
		// the application hashes, and a class gets loaded further out while it runs
		Assertions.assertFalse( PlatformWork.inside( new StackTraceElement[] { f( "java.security.MessageDigest", "getInstance" ),
			f( "com.acme.ticketbook.Ticket", "hash" ), f( "java.lang.ClassLoader", "loadClass" ) } ) );
		// a library's class initializer closer in than the class loader still counts
		Assertions.assertFalse( PlatformWork.inside( new StackTraceElement[] { f( "java.io.File", "<init>" ),
			f( "com.google.common.Foo", "<clinit>" ), f( "java.lang.ClassLoader", "loadClass" ) } ) );
		// a page fetching an https address, the platform does a handshake for it and never reaches a class loader
		Assertions.assertFalse( PlatformWork.inside( new StackTraceElement[] { f( "java.security.SecureRandom", "<init>" ),
			f( "sun.security.ssl.SSLContextImpl", "engineInit" ), f( "java.net.URL", "openConnection" ), f( "org.apache.jsp.ssrf_jsp", "_jspService" ) } ) );
		Assertions.assertFalse( PlatformWork.inside( null ) );
		Assertions.assertFalse( PlatformWork.inside( new StackTraceElement[0] ) );
	}

	@Test
	void theCallBeingWatchedIsNotTheWorkItself() {
		Assertions.assertFalse( PlatformWork.inside( new StackTraceElement[] { f( "java.lang.ClassLoader", "defineClass" ), f( "org.apache.jsp.x_jsp", "_jspService" ) } ),
			"an application can call a class loader's method, only what is further out counts" );
	}

	@Test
	void anEntryMatchesWholeNamesAndWhatIsInsideThem() {
		PlatformWork.configure( List.of( "java.lang.ClassLoader" ) );
		Assertions.assertTrue( PlatformWork.inside( new StackTraceElement[] { f( "java.io.File", "<init>" ), f( "java.lang.ClassLoader", "loadClass" ) } ) );
		Assertions.assertTrue( PlatformWork.inside( new StackTraceElement[] { f( "java.io.File", "<init>" ), f( "java.lang.ClassLoader$Inner", "run" ) } ), "inner classes" );
		Assertions.assertFalse( PlatformWork.inside( new StackTraceElement[] { f( "java.io.File", "<init>" ), f( "java.lang.ClassLoaderHelper", "load" ) } ),
			"a different class that only starts with the same letters" );
	}

	@Test
	void theListCanBeChangedOrEmptied() {
		StackTraceElement[] vendor = { f( "java.io.File", "<init>" ), f( "javax.vendor.AppLoader", "load" ) };
		Assertions.assertFalse( PlatformWork.inside( vendor ) );
		PlatformWork.configure( List.of( "javax.vendor" ) );
		Assertions.assertTrue( PlatformWork.inside( vendor ) );
		Assertions.assertFalse( PlatformWork.inside( JAR_CHECK ), "the list replaces the default, it doesn't add to it" );
		PlatformWork.configure( List.of() );
		Assertions.assertFalse( PlatformWork.inside( JAR_CHECK ), "an empty list ignores nothing" );
		PlatformWork.configure( null );
		Assertions.assertTrue( PlatformWork.inside( JAR_CHECK ), "no list is the default" );
	}

	@Test
	void theJotsFileSetsTheListAndAWrongOneKeepsTheDefault(@TempDir Path dir) throws Exception {
		Files.writeString( dir.resolve( "none.jot" ), "sensors: []\n" );
		Path jots = dir.resolve( "jots.yaml" );
		Files.writeString( jots, "jots:\n- none.jot\nignore:\n- javax.vendor\n- org.other.loader\n" );
		ConfigReader.readJotsFile( jots.toFile() );
		Assertions.assertEquals( List.of( "javax.vendor", "org.other.loader" ), PlatformWork.ignored() );
		int before = ConfigReader.getProblems().size();
		Files.writeString( jots, "jots:\n- none.jot\nignore: java.lang.ClassLoader\nignorr:\n- x\n" );
		PlatformWork.configure( null );
		ConfigReader.readJotsFile( jots.toFile() );
		List<String> said = ConfigReader.getProblems().subList( before, ConfigReader.getProblems().size() );
		Assertions.assertEquals( PlatformWork.DEFAULT_IGNORE, PlatformWork.ignored(), "a list that isn't a list is not used" );
		Assertions.assertTrue( said.stream().anyMatch( x -> x.contains( "ignore must be a list" ) ), said.toString() );
		Assertions.assertTrue( said.stream().anyMatch( x -> x.contains( "ignorr is not a setting of a jots file" ) ), said.toString() );
	}

	private static class Recorder implements EventSink {
		final List<Event> events = new ArrayList<Event>();
		public void accept(Event e) { events.add( e ); }
	}

	private Recorder run(Runnable call) {
		Recorder r = new Recorder();
		EventBus.configure( List.of( r ), 10 );
		try {
			call.run();
		} finally {
			EventBus.shutdown();
		}
		return r;
	}

	@Test
	void aSensorLeavesTheWorkOutAndARuleStillSeesIt() {
		Sensor observes = new Sensor().name( "pw-observes" ).method( "a.b.Class.method" ).capture( "#P0" );
		Sensor blocks = new Sensor().name( "pw-blocks" ).description( "Seen" ).method( "a.b.Class.method" ).capture( "#P0" ).blockWhen( "true" ).protect( false );
		Recorder r = run( () -> {
			observes.execute( "test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo", JAR_CHECK );
			blocks.execute( "test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo", JAR_CHECK );
		} );
		Assertions.assertEquals( List.of( "pw-blocks-monitored" ), r.events.stream().map( Event::getRule ).toList(),
			"the sensor said nothing for the platform's work and the rule still reported it" );
		StackTraceElement[] app = { f( "java.security.MessageDigest", "getInstance" ), f( "com.acme.Ticket", "hash" ), f( "java.lang.ClassLoader", "loadClass" ) };
		Recorder again = run( () -> observes.execute( "test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo", app ) );
		Assertions.assertEquals( List.of( "pw-observes" ), again.events.stream().map( Event::getRule ).toList(), "what the application did is still reported" );
	}
}
