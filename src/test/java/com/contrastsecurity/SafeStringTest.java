package com.contrastsecurity;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.Vector;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.SafeString;

class SafeStringTest {

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
