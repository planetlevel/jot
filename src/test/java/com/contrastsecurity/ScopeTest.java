package com.contrastsecurity;

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

}
