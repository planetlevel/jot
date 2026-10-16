package org.openolly;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class JotScopeListenerTest {

	private final JotScopeListener listener = new JotScopeListener();

	@Test
	void testScopeIsHeldWhileAClassIsBeingTransformed() {
		Assertions.assertFalse( JotScope.active() );
		listener.onDiscovery( "a.B", null, null, false );
		try {
			Assertions.assertTrue( JotScope.active() );
		} finally {
			listener.onComplete( "a.B", null, null, false );
		}
		Assertions.assertFalse( JotScope.active() );
	}

	@Test
	void testTransformationsThatLoadOtherClassesNest() {
		listener.onDiscovery( "a.Outer", null, null, false );
		listener.onDiscovery( "a.Inner", null, null, false );   // transforming one class loaded another
		listener.onComplete( "a.Inner", null, null, false );
		Assertions.assertTrue( JotScope.active(), "still inside the outer class" );
		listener.onComplete( "a.Outer", null, null, false );
		Assertions.assertFalse( JotScope.active() );
	}

	@Test
	void testASensorDoesNotFireWhileAClassIsBeingTransformed() {
		Sensor s = new Sensor().method( "a.b.Class.method" ).capture( "#P0" );
		listener.onDiscovery( "a.B", null, null, false );
		try {
			Assertions.assertTrue( s.execute( "test", "sig", "foo", new String[] { "bar" }, "zoo" ).isEmpty() );
		} finally {
			listener.onComplete( "a.B", null, null, false );
		}
		Assertions.assertEquals( 1, s.execute( "test", "sig", "foo", new String[] { "bar" }, "zoo" ).size() );
	}

}
