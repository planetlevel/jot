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
   
}
