package org.openolly;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AnnotationTest {

	enum Level { LOW, HIGH }

	@Retention(RetentionPolicy.RUNTIME)
	@Target({ ElementType.METHOD, ElementType.TYPE })
	@interface Secured {
		String[] roles() default {};
		String value() default "";
		int rank() default 0;
		Level level() default Level.LOW;
		Class<?> via() default Object.class;
	}

	static class Service {
		@Secured(roles = { "admin", "auditor" }, value = "ledger", rank = 3, level = Level.HIGH, via = String.class)
		public String read(String id, int count) { return id; }

		public void plain() { }
	}

	@Secured(roles = "ops")
	static class Whole {
		public void any() { }

		@Secured(roles = "own")
		public void mine() { }
	}

	private static final String READ = "(Ljava/lang/String;I)Ljava/lang/String;";

	@Test
	void annotationLocatorIsRecognised() {
		MethodLocator loc = new MethodLocator( "@org.openolly.AnnotationTest$Secured" );
		Assertions.assertTrue( loc.isAnnotation() );
		Assertions.assertEquals( "org.openolly.AnnotationTest$Secured", loc.annotationName() );
		Assertions.assertFalse( new MethodLocator( "a.b.C.m" ).isAnnotation() );
	}

	@Test
	void attributesComeBackAsPlainValues() {
		MethodLocator loc = new MethodLocator( "@" + Secured.class.getName() );
		Map<String, Object> v = loc.annotationValues( Service.class, "read", READ );
		Assertions.assertEquals( Arrays.asList( "admin", "auditor" ), v.get( "roles" ) );
		Assertions.assertEquals( "ledger", v.get( "value" ) );
		Assertions.assertEquals( 3, v.get( "rank" ) );
		Assertions.assertEquals( "HIGH", v.get( "level" ) );
		Assertions.assertEquals( "java.lang.String", v.get( "via" ) );
	}

	@Test
	void defaultsAreIncluded() {
		MethodLocator loc = new MethodLocator( "@" + Secured.class.getName() );
		Map<String, Object> v = loc.annotationValues( Whole.class, "any", "()V" );
		Assertions.assertEquals( Arrays.asList( "ops" ), v.get( "roles" ) );
		Assertions.assertEquals( "", v.get( "value" ) );
	}

	@Test
	void theMethodsOwnAnnotationWinsOverItsClasss() {
		MethodLocator loc = new MethodLocator( "@" + Secured.class.getName() );
		Assertions.assertEquals( Arrays.asList( "own" ), loc.annotationValues( Whole.class, "mine", "()V" ).get( "roles" ) );
	}

	@Test
	void aMethodWithNoAnnotationHasNoValues() {
		MethodLocator loc = new MethodLocator( "@" + Secured.class.getName() );
		Assertions.assertNull( loc.annotationValues( Service.class, "plain", "()V" ) );
		Assertions.assertNull( loc.annotationValues( Service.class, "missing", "()V" ) );
		Assertions.assertNull( new MethodLocator( "a.b.C.m" ).annotationValues( Service.class, "read", READ ) );
	}

	@Test
	void descriptorMatchesTheJvmsForm() throws Exception {
		Assertions.assertEquals( READ, MethodLocator.descriptor( Service.class.getMethod( "read", String.class, int.class ) ) );
		Assertions.assertEquals( "([J[[Ljava/lang/Object;)V",
				MethodLocator.descriptor( AnnotationTest.class.getDeclaredMethod( "shapes", long[].class, Object[][].class ) ) );
	}

	static void shapes(long[] a, Object[][] b) { }

	@Test
	void capturesCanReadTheAttributes() {
		Sensor s = new Sensor().capture( "#ANNOTATION.roles" );
		Map<String, Object> annotation = new MethodLocator( "@" + Secured.class.getName() ).annotationValues( Service.class, "read", READ );
		List<Object> out = s.execute( "test", "a.B.read", null, new Object[0], null, new Exception().getStackTrace(), annotation );
		Assertions.assertEquals( Arrays.asList( "admin", "auditor" ), out );
	}

	@Test
	void capturesCanIndexTheAttributes() {
		Sensor s = new Sensor().capture( "#CALLER + ' needs ' + #ANNOTATION['value'] + ' ' + #ANNOTATION['rank']" );
		Map<String, Object> annotation = new MethodLocator( "@" + Secured.class.getName() ).annotationValues( Service.class, "read", READ );
		List<Object> out = s.execute( "test", "a.B.read", null, new Object[0], null, new Exception().getStackTrace(), annotation );
		Assertions.assertEquals( Arrays.asList( "a.B.read needs ledger 3" ), out );
	}

	@Test
	void withoutAnAnnotationTheVariableIsNull() {
		Sensor s = new Sensor().capture( "#ANNOTATION == null ? 'none' : 'some'" );
		List<Object> out = s.execute( "test", "a.B.read", null, new Object[0], null, new Exception().getStackTrace() );
		Assertions.assertEquals( Arrays.asList( "none" ), out );
	}

	@Test
	void sensorAddsTheJakartaTwinOfAnAnnotation() {
		Sensor s = new Sensor().method( "@javax.annotation.security.RolesAllowed" );
		Assertions.assertEquals( 2, s.getMethods().size() );
		Assertions.assertEquals( "jakarta.annotation.security.RolesAllowed", s.getMethods().get( 1 ).annotationName() );
	}

	@Test
	void sensorAnnotationFor() {
		Sensor s = new Sensor().method( "@" + Secured.class.getName() ).method( "a.b.C.m" );
		Assertions.assertNotNull( s.annotationFor( 0, Service.class, "read", READ ) );
		Assertions.assertNull( s.annotationFor( 1, Service.class, "read", READ ) );
	}

	@Test
	void aScopeCantBeAnAnnotation() {
		Sensor s = new Sensor().scope( "@" + Secured.class.getName() );
		Assertions.assertTrue( s.getScopes().isEmpty() );
	}
}
