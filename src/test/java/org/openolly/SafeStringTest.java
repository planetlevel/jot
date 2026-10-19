package org.openolly;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.Vector;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SafeStringTest {

	@Test
	void valuesThatAreTheirOwnTextAreRecordedAsThatText() {
		Assertions.assertEquals( "/var/log/app.log", SafeString.format( new java.io.File( "/var/log/app.log" ), false ) );
		Assertions.assertEquals( "/var/log/app.log", SafeString.format( java.nio.file.Paths.get( "/var/log/app.log" ), false ) );
		Assertions.assertEquals( "2048", SafeString.format( 2048, false ) );
		Assertions.assertEquals( "true", SafeString.format( Boolean.TRUE, false ) );
		Assertions.assertEquals( "x", SafeString.format( 'x', false ) );
		Assertions.assertEquals( "ab", SafeString.format( new StringBuilder( "ab" ), false ) );
		Assertions.assertEquals( "RUNNABLE", SafeString.format( Thread.State.RUNNABLE, false ) );
		Assertions.assertEquals( "http://x/y", SafeString.format( java.net.URI.create( "http://x/y" ), false ) );
		Assertions.assertEquals( "[1, 2]", SafeString.format( new Integer[] { 1, 2 }, false ), "and inside an array" );
	}

	@Test
	void anyOtherObjectIsStillShownWithItsClass() {
		Assertions.assertTrue( SafeString.format( new java.util.Date( 0 ), false ).startsWith( "{class java.util.Date:" ) );
	}

	@Test
	void testNull() {
        Assertions.assertEquals( "null" , SafeString.format(null,false));		
	}
	
	@Test
	void testString() {
        Assertions.assertEquals( "foobar" , SafeString.format("foobar",false));
	}
	
	@Test
	void testEntry() {
		Map<String,String> map = new HashMap<String,String>();
		map.put("foo","bar");
		Map.Entry entry = map.entrySet().iterator().next();
        Assertions.assertEquals( "[foo=bar]" , SafeString.format(entry,false));
	}
	
	@Test
	void testEnumeration() {
		Vector<String> v = new Vector();
		v.add( "foo" );
		v.add( "bar" );
		Enumeration e = v.elements();
        Assertions.assertEquals( "[foo, bar]" , SafeString.format(e,false));
	}
	
	@Test
	void testArray() {
		Object[] arr = {"foo","bar"};
        Assertions.assertEquals( "[foo, bar]" , SafeString.format(arr,false));
	}

	void testPrimitiveArray() {
		int[] arr = {1,2};
        Assertions.assertEquals( "[1, 2]" , SafeString.format(arr,false));
	}

	@Test
	void testDeepArray() {
		Object[] arr = {"foo","bar",new String[]{"blue","red"}};
        Assertions.assertEquals( "[foo, bar, [blue, red]]" , SafeString.format(arr,false));
	}

	@Test
	void testCollection() {
		TreeSet<String> set = new TreeSet();
		set.add( "foo" );
		set.add( "bar" );
        Assertions.assertEquals( "[bar, foo]" , SafeString.format(set,false));
	}
	
	@Test
	void testMap() {
		Map<String,String> map = new HashMap<String,String>();
		map.put("foo1","bar");
		map.put("foo2","bar");
        Assertions.assertEquals( "[[foo1=bar],[foo2=bar]]", SafeString.format(map,false));
	}

//	
//    @BeforeAll
//    static void setup(){
//        System.out.println("@BeforeAll executed");
//    }
//     
//    @BeforeEach
//    void setupThis(){
//        System.out.println("@BeforeEach executed");
//    }
//     	
//    @AfterEach
//    void tearThis(){
//        System.out.println("@AfterEach executed");
//    }
//     
//    @AfterAll
//    static void tear(){
//        System.out.println("@AfterAll executed");
//    }
    
}
