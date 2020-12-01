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
	
}

