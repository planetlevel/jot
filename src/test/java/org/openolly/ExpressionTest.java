package org.openolly;

import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ExpressionTest {

	@Test
	void testConvert() throws Exception {
		Vector<String> v = new Vector();
		v.add( "foo" );
		v.add( "bar" );
		Enumeration e = v.elements();
		Expression expr = new Expression("#P0");
		Object o = expr.convert( e );
        Assertions.assertTrue( List.class.isAssignableFrom( o.getClass() ) );		
        Assertions.assertEquals( 2, ((List)o).size() );		
	}
	
	@Test
	void testNull() throws Exception {
		Expression expr = new Expression("#P0");
		Object o = expr.convert( null );
        Assertions.assertEquals( null, o );		
	}
   
	@Test
	void threadsRunningTheSameExpressionEachSeeTheirOwnArguments() throws Exception {
		Expression expr = new Expression("#P0 + ':' + #P1");
		java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool( 8 );
		java.util.List<java.util.concurrent.Future<Integer>> results = new java.util.ArrayList<>();
		for ( int t = 0; t < 8; t++ ) {
			final int id = t;
			results.add( pool.submit( () -> {
				int wrong = 0;
				for ( int i = 0; i < 20000; i++ ) {
					Object o = expr.execute( null, new Object[] { "t" + id, i }, null, null, null );
					if ( !( "t" + id + ":" + i ).equals( o ) ) wrong++;
				}
				return wrong;
			} ) );
		}
		int wrong = 0;
		for ( java.util.concurrent.Future<Integer> f : results ) wrong += f.get();
		pool.shutdown();
		Assertions.assertEquals( 0, wrong, "a request was given another request's values" );
	}

	@Test
	void aCallWithFewerArgumentsDoesNotSeeTheLastCallsExtra() throws Exception {
		Expression expr = new Expression("#P1");
		Assertions.assertEquals( "b", expr.execute( null, new Object[] { "a", "b" }, null, null, null ) );
		Assertions.assertNull( expr.execute( null, new Object[] { "a" }, null, null, null ) );
	}

}
