package org.openolly;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.advice.scope.BinaryScope;

public class ScopeTest {

	@Test
	public void testEnterScope() {
		BinaryScope scope1 = new BinaryScope();
		scope1.enterScope();
        Assertions.assertTrue( scope1.inScope() );
	}

	private BinaryScope scope = new BinaryScope();
	private int x = 0;
	
	public void two(int b) {
		if ( scope.inScope() ) return;
		scope.enterScope();
		x = 11;
		scope.leaveScope();
	}
	public void one(int b) {
		if ( scope.inScope() ) return;
		scope.enterScope();
		x = 5;
		two(x);
		scope.leaveScope();
	}
	
	@Test
	public void testInNestedSensor() {
		one(10);
        Assertions.assertEquals( 5, x );
	}

	private static StackTraceElement frame(String method) {
		return new StackTraceElement("com.acme.Vuln", method, "Vuln.java", 1);
	}

	@Test
	public void testLeakedScopeIsHealedWhenScopeMethodNotOnStack() {
		MethodLocator scope = new MethodLocator("com.acme.Vuln.lookup");
		scope.enterScope(); // never left, as when a constructor throws
		scope.healIfLeaked( new StackTraceElement[] { frame("main") } );
		Assertions.assertFalse( scope.inScope() );
		Assertions.assertEquals( 0, scope.scopeValue() );
	}

	@Test
	public void testScopeKeptWhenScopeMethodOnStack() {
		MethodLocator scope = new MethodLocator("com.acme.Vuln.lookup");
		scope.enterScope();
		scope.healIfLeaked( new StackTraceElement[] { frame("exec"), frame("lookup"), frame("main") } );
		Assertions.assertTrue( scope.inScope() );
	}

	@Test
	public void testConstructorScopeHealedOnlyByConstructorFrame() {
		MethodLocator scope = new MethodLocator("com.acme.Vuln.<init>");
		scope.enterScope();
		scope.healIfLeaked( new StackTraceElement[] { frame("exec"), frame("<init>"), frame("main") } );
		Assertions.assertTrue( scope.inScope() );
		scope.healIfLeaked( new StackTraceElement[] { frame("exec"), frame("lookup"), frame("main") } );
		Assertions.assertFalse( scope.inScope() );
	}

	@Test
	public void testHealIgnoresIdleScopeAndNullStack() {
		MethodLocator scope = new MethodLocator("com.acme.Vuln.lookup");
		scope.healIfLeaked( new StackTraceElement[] { frame("main") } );
		Assertions.assertEquals( 0, scope.scopeValue() );
		scope.enterScope();
		scope.healIfLeaked( null );
		Assertions.assertTrue( scope.inScope() );
	}

}
