package org.openolly;

import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.advice.SensorException;

class SensorTest {

	@Test
	void testExecute() {
		Sensor s = new Sensor().capture("#P0");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[bar]", SafeString.format(ret, false));
	}

	@Test
	void testExecuteExpression() {
		Sensor s = new Sensor().capture("#P0.toUpperCase()");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[BAR]", SafeString.format(ret, false));
	}

	@Test
	void testNoScope() {
		Sensor s = new Sensor().method("a.Class.method").capture("#P0").scope("s.Class.method");
		Object ret = s.execute("test", "sig", "foo", new String[] { "bar" }, "zoo", new Exception().getStackTrace());
		Assertions.assertEquals("[]", SafeString.format(ret, false));
	}

	@Test
	void testInScope() {
		Sensor s = new Sensor().method("a.Class.method").capture("#P0").scope("s.Class.method");

		s.getScopes().iterator().next().enterScope();

		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[bar]", SafeString.format(ret, false));
	}

	@Test
	void testNotInScope() {
		Sensor s = new Sensor().method("a.Class.method").capture("#P0").scope("s.Class.method");

		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[]", SafeString.format(ret, false));
	}

	@Test
	void testNegativeScope() {
		Sensor s = new Sensor().method("a.Class.method").capture("#P0").scope("!s.Class.method");

		s.getScopes().iterator().next().enterScope();

		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[]", SafeString.format(ret, false));
	}

	@Test
	void testException() {
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0").exception("Exception");

		try {
			Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
					new Exception().getStackTrace());
		} catch (SensorException e) {
			return;
		}
		fail("Did not throw SensorException");
	}

	@Test
	void testMatches() {
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0").matcher("ba");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[bar]", SafeString.format(ret, false));
	}

	@Test
	void testNotMatches() {
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0").matcher("\\[fo");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[]", SafeString.format(ret, false));
	}

	@Test
	void testRoleCheckRecordsTheRoleAndTheAnswerButNotNulls() {
		// the auth-role-check sensor, which captures like ADMIN: true and leaves out a null role or a null answer
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0 + \": \" + #RET").matcher("!^null:").matcher("!: null$");
		StackTraceElement[] stack = new Exception().getStackTrace();
		Assertions.assertEquals("[ADMIN: true]", SafeString.format(s.execute("test", "a.b.Class.Method", "foo", new Object[] { "ADMIN" }, Boolean.TRUE, stack), false));
		Assertions.assertEquals("[MANAGER: false]", SafeString.format(s.execute("test", "a.b.Class.Method", "foo", new Object[] { "MANAGER" }, Boolean.FALSE, stack), false));
		Assertions.assertEquals("[nullable: false]", SafeString.format(s.execute("test", "a.b.Class.Method", "foo", new Object[] { "nullable" }, Boolean.FALSE, stack), false),
				"a role with null in its name is still a role");
		Assertions.assertEquals("[]", SafeString.format(s.execute("test", "a.b.Class.Method", "foo", new Object[] { null }, Boolean.FALSE, stack), false), "no role");
		Assertions.assertEquals("[]", SafeString.format(s.execute("test", "a.b.Class.Method", "foo", new Object[] { "ADMIN" }, null, stack), false), "no answer");
	}

	@Test
	void testCipherUseRecordsTheAlgorithmAndTheModeFromInit() throws Exception {
		// the crypto-cipher sensor, on Cipher.init, which says what was really used and for what
		Sensor s = new Sensor().method("javax.crypto.Cipher.init")
				.capture("#OBJ.getAlgorithm() + \": \" + (#P0 == 1 ? \"encrypt\" : #P0 == 2 ? \"decrypt\" : \"other\")");
		StackTraceElement[] stack = new Exception().getStackTrace();
		javax.crypto.SecretKey key = new javax.crypto.spec.SecretKeySpec(new byte[16], "AES");
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
		Assertions.assertEquals("[AES/CBC/PKCS5Padding: encrypt]", SafeString.format(
				s.execute("test", "javax.crypto.Cipher.init", cipher, new Object[] { javax.crypto.Cipher.ENCRYPT_MODE, key }, null, stack), false));
		Assertions.assertEquals("[AES/CBC/PKCS5Padding: decrypt]", SafeString.format(
				s.execute("test", "javax.crypto.Cipher.init", cipher, new Object[] { javax.crypto.Cipher.DECRYPT_MODE, key }, null, stack), false));
		Assertions.assertEquals("[AES/CBC/PKCS5Padding: other]", SafeString.format(
				s.execute("test", "javax.crypto.Cipher.init", cipher, new Object[] { javax.crypto.Cipher.WRAP_MODE, key }, null, stack), false));
		Assertions.assertFalse(SafeString.format(
				s.execute("test", "javax.crypto.Cipher.init", cipher, new Object[] { 1, key }, null, stack), false).contains("0000"), "the key itself is never recorded");
	}

	@Test
	void testNegativeMatches() {
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0").matcher("!^\\[ca");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[bar]", SafeString.format(ret, false));
	}

	@Test
	void testMultiPositiveMatches() {
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0").matcher("bar").matcher("foo");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[bar]", SafeString.format(ret, false));
	}

	@Test
	void testMultiNegativeNonMatches() {
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0").matcher("!ca").matcher("!da").matcher("!ea");
		Object ret = s.execute("test", "a.b.Class.Method", "obj", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[bar]", SafeString.format(ret, false));
		Object ret2 = s.execute("test", "a.b.Class.Method", "obj", new String[] { "acad" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[]", SafeString.format(ret2, false));
	}

	@Test
	void testMultiNegativeYesMatches() {
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0").matcher("!ca").matcher("!da").matcher("!ba");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[]", SafeString.format(ret, false));
	}

	@Test
	void testMixedMatches() {
		Sensor s = new Sensor().method("a.b.Class.method").capture("#P0").matcher("ba").matcher("!ba");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo",
				new Exception().getStackTrace());
		Assertions.assertEquals("[]", SafeString.format(ret, false));
	}

	@Test
	void testMiddleMatch() {
		Sensor s = new Sensor()
				.method("a.b.Class.method")
				.capture("#P0")
				.matcher("!\\/apache\\-tomcat");
		Object ret = s.execute( "test", "a.b.Class.Method", "foo", new String[]{"/Users/jeffwilliams/git/apache-tomcat-8.5.43/lib/catalina.jar"}, "zoo", new Exception().getStackTrace() );
        Assertions.assertEquals( "[]" , SafeString.format(ret, false));		
	}
	
	@Test
	void testCurrentStackLooksLikeAdviceCaptured() {
		StackTraceElement[] stack = Sensor.currentStack();
		Assertions.assertEquals("getStackTrace", stack[0].getMethodName());
		// JOT's own frames are gone, so [1] is the method the advice would be inlined in
		Assertions.assertEquals("testCurrentStackLooksLikeAdviceCaptured", stack[1].getMethodName());
		Assertions.assertEquals(SensorTest.class.getName(), stack[1].getClassName());
	}

	@Test
	void testExecuteWithoutStackStillCapturesAndUsesStack() {
		Sensor s = new Sensor().method("a.Class.method").capture("#P0");
		Object ret = s.execute("test", "a.b.Class.Method", "foo", new String[] { "bar" }, "zoo");
		Assertions.assertEquals("[bar]", SafeString.format(ret, false));
	}


	/** Stands in for application code that has a sensor on one of its methods. */
	public static class Probe {
		Sensor watcher;
		java.util.List<Object> seen;

		public String get() {
			seen = watcher.execute( "test", "Probe.get", this, new Object[0], null );
			return "from-probe";
		}
	}

	@Test
	void testNoSensorFiresWhileAnotherSensorRuns() {
		Sensor watcher = new Sensor().capture("'watched'");
		Sensor outer = new Sensor().capture("#P0.get()");
		Probe probe = new Probe();
		probe.watcher = watcher;

		Object ret = outer.execute( "test", "sig", null, new Object[] { probe }, null );

		Assertions.assertEquals( "[from-probe]", SafeString.format( ret, false ) );
		Assertions.assertEquals( "[]", SafeString.format( probe.seen, false ), "the nested sensor must not fire" );
		Assertions.assertFalse( JotScope.active(), "the guard must be released" );
		Assertions.assertEquals( "[watched]", SafeString.format( watcher.execute( "test", "sig", null, new Object[0], null ), false ) );
	}

	@Test
	void testGuardIsReleasedWhenASensorBlocks() {
		Sensor blocker = new Sensor().capture("#P0").exception("blocked");
		Assertions.assertThrows( SensorException.class,
			() -> blocker.execute( "test", "sig", null, new Object[] { "x" }, null ) );
		Assertions.assertFalse( JotScope.active() );
	}

	@Test
	void testSensorsDoNotFireOnAThreadThatRunsJotCode() throws Exception {
		Sensor s = new Sensor().capture("#P0");
		java.util.concurrent.atomic.AtomicReference<java.util.List<Object>> result = new java.util.concurrent.atomic.AtomicReference<>();
		Thread t = new Thread( () -> {
			JotScope.enterForThread();
			result.set( s.execute( "test", "sig", null, new Object[] { "x" }, null ) );
		} );
		t.start();
		t.join();
		Assertions.assertTrue( result.get().isEmpty() );
	}


	private static java.util.List<String> names(java.util.List<MethodLocator> locators) {
		java.util.List<String> out = new java.util.ArrayList<String>();
		for ( MethodLocator l : locators ) out.add( l.className() + "." + l.methodName() );
		return out;
	}

	// A JOT watches the names it lists. A servlet sensor lists both spellings, nothing is added behind its back.
	@Test
	void testAMethodIsWatchedExactlyAsWritten() {
		Sensor javax = new Sensor().method( "javax.servlet.Servlet.service" );
		Assertions.assertEquals( java.util.List.of( "javax.servlet.Servlet.service" ), names( javax.getMethods() ) );
		Sensor jakarta = new Sensor().method( "jakarta.servlet.ServletRequest.isUserInRole" );
		Assertions.assertEquals( java.util.List.of( "jakarta.servlet.ServletRequest.isUserInRole" ), names( jakarta.getMethods() ) );
	}

	@Test
	void testNamingBothSpellingsWatchesBothWithTheirOwnIndex() {
		Sensor s = new Sensor().methods( java.util.List.of( "javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service" ) );
		Assertions.assertEquals( java.util.List.of( "javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service" ), names( s.getMethods() ) );
		Assertions.assertEquals( 0, s.getMethods().get( 0 ).getIndex() );
		Assertions.assertEquals( 1, s.getMethods().get( 1 ).getIndex() );
	}

	@Test
	void testNamingTheSameMethodTwiceDoesNotInstrumentTwice() {
		Sensor s = new Sensor().methods( java.util.List.of( "javax.servlet.Servlet.service", "javax.servlet.Servlet.service" ) );
		Assertions.assertEquals( 1, s.getMethods().size() );
	}

	@Test
	void testOtherMethodsAreTakenAsWritten() {
		Sensor s = new Sensor().method( "javax.crypto.Cipher.getInstance" ).method( "a.b.Servlet.service" );
		Assertions.assertEquals( java.util.List.of( "javax.crypto.Cipher.getInstance", "a.b.Servlet.service" ), names( s.getMethods() ) );
	}

	@Test
	void testScopesAreTakenAsWrittenAndGetTheirOwnIndex() {
		Sensor s = new Sensor().scope( "x.Y.z" ).scope( "javax.servlet.Servlet.service" ).scope( "jakarta.servlet.Servlet.service" );
		Assertions.assertEquals( java.util.List.of( "x.Y.z", "javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service" ),
				names( s.getScopes() ) );
		for ( int i = 0; i < 3; i++ ) Assertions.assertEquals( i, s.getScopes().get( i ).getIndex() );
	}

	@Test
	void testAScopeWrittenForOneSpellingDoesNotCoverTheOther() {
		Sensor s = new Sensor().scope( "javax.servlet.Servlet.service" );
		Assertions.assertEquals( 1, s.getScopes().size() );
	}

	@Test
	void testNegativeScopesAreTakenAsWritten() {
		Sensor s = new Sensor().scope( "!javax.servlet.Servlet.service" );
		Assertions.assertEquals( java.util.List.of( "javax.servlet.Servlet.service" ), names( s.getScopes() ) );
		Assertions.assertTrue( s.getScopes().get( 0 ).isNegative() );
	}

	@Test
	void testBeingInEitherListedServletFlavourEnablesTheSensor() {
		Sensor s = new Sensor().method( "a.Class.method" ).capture( "#P0" )
				.scope( "javax.servlet.Servlet.service" ).scope( "jakarta.servlet.Servlet.service" );
		s.getScopes().get( 1 ).enterScope();  // the jakarta one
		Object ret = s.execute( "test", "sig", "foo", new String[] { "bar" }, "zoo", new Exception().getStackTrace() );
		Assertions.assertEquals( "[bar]", SafeString.format( ret, false ) );
	}

}
