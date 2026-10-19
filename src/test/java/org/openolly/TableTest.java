package org.openolly;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.reporting.Event;
import org.openolly.reporting.Report;
import org.openolly.reporting.RouteGraph;
import org.openolly.reporting.Trace;

class TableTest {

	private static final StackTraceElement[] stack = Thread.currentThread().getStackTrace();

	private static Event event(String rule, String capture) {
		return new Event( rule, capture, stack );
	}

	private static Event fields(String rule, Object... pairs) {
		java.util.Map<String, Object> data = new java.util.LinkedHashMap<String, Object>();
		for ( int i = 0; i < pairs.length; i += 2 ) data.put( (String)pairs[i], pairs[i + 1] );
		return new Event( rule, Sensor.text( data ), stack, data );
	}

	@Test
	void testCompare() {
		Trace.start();
		Report t = new Report().name("Test Report").type("compare").rows("rule1.path").cols("rule2.role").value("rule2.allowed").validate();
		t.accept( fields("rule1", "path", "/route1") );
		t.accept( fields("rule2", "role", "RoleA", "allowed", true) );
		t.accept( fields("rule2", "role", "RoleB", "allowed", false) );
		Assertions.assertEquals("[true]", t.get("/route1", "RoleA").toString() );
		Assertions.assertEquals("[false]", t.get("/route1", "RoleB").toString() );
	}

	@Test
	void testCompareWithoutAValueMarksTheCell() {
		Trace.start();
		Report t = new Report().name("Test Report").type("compare").rows("rule1.path").cols("rule2.user").validate();
		t.accept( fields("rule1", "path", "/route1") );
		t.accept( fields("rule2", "user", "alice") );
		Assertions.assertEquals("[x]", t.get("/route1", "alice").toString() );
	}

	@Test
	void testAFieldThatIsAListFillsOneCellEach() {
		Trace.start();
		Report t = new Report().name("Test Report").type("table").rows("rule1.path").cols("rule2.names").validate();
		t.accept( fields("rule1", "path", "/route1") );
		t.accept( fields("rule2", "names", List.of( "a", "b" ) ) );
		Assertions.assertEquals("[a, b]", t.get("/route1", "rule2.names").toString() );
	}

	@Test
	void testAValueFieldFromAnotherSensorIsRefused() {
		Assertions.assertThrows( IllegalArgumentException.class,
			() -> new Report().name("r").type("compare").rows("a.p").cols("b.x").value("c.y").validate() );
	}

	@Test
	void testRowMayArriveAfterColumns() {
		Trace.start();
		Report t = new Report().name("Test Report").type("table").rows("rule1").cols("rule2, rule3").validate();
		t.accept( event("rule2", "AES") );
		t.accept( event("rule3", "x") );
		t.accept( event("rule1", "/route1") );
		Assertions.assertEquals("[AES]", t.get("/route1", "rule2").toString() );
		Assertions.assertEquals("[x]", t.get("/route1", "rule3").toString() );
	}

	@Test
	void testSeparateRequestsDoNotMix() {
		Report t = new Report().name("Test Report").type("table").rows("rule1").cols("rule2").validate();
		Trace.start();
		t.accept( event("rule1", "/a") );
		t.accept( event("rule2", "AES") );
		Trace.start();
		t.accept( event("rule1", "/b") );
		t.accept( event("rule2", "DES") );
		Assertions.assertEquals("[AES]", t.get("/a", "rule2").toString() );
		Assertions.assertEquals("[DES]", t.get("/b", "rule2").toString() );
	}

	@Test
	void testList() {
		Report t = new Report().name("Test Report").type("list").cols("rule2").validate();
		for ( String algorithm : List.of( "DES", "AES", "CBC", "MD5" ) ) {
			t.accept( event("rule2", algorithm) );
		}
		t.accept( event("other", "ignored") );
		Assertions.assertEquals("[AES, CBC, DES, MD5]", t.get(stack[2].toString(), "rule2").toString() );
		Assertions.assertTrue( t.render().contains( "AES,CBC,DES,MD5" ) );
	}

	@Test
	void testRenderIsEmptyWithoutEvents() {
		Assertions.assertEquals( "", new Report().name("Empty").type("list").cols("rule2").render() );
	}

	@Test
	void testRowsAreBounded() {
		Report t = new Report().name("Bounded").type("list").cols("rule2").maxRows(2).validate();
		for ( int i = 0; i < 5; i++ ) {
			t.accept( new Event( "rule2", "v" + i, new StackTraceElement[] {
				stack[0], stack[1], new StackTraceElement( "C" + i, "m", "C.java", i + 1 ) } ) );
		}
		String out = t.render();
		Assertions.assertTrue( out.contains( "3 entries not shown" ), out );
	}

	@Test
	void testValidateRejectsIncompleteReports() {
		Assertions.assertThrows( IllegalArgumentException.class,
			() -> new Report().name("x").type("table").cols("a").validate() );
		Assertions.assertThrows( IllegalArgumentException.class,
			() -> new Report().name("x").type("series") );
	}

	@Test
	void testRouteGraph() {
		Trace.start();
		RouteGraph g = new RouteGraph( "Routes", "route", List.of( "forward" ) );
		g.accept( event("route", "/home") );
		g.accept( event("query", "select 1") );
		g.accept( event("forward", "/other") );
		g.accept( event("cipher", "AES") );
		Trace.start();
		g.accept( event("route", "/logo.png") );
		g.accept( event("query", "ignored") );
		String dot = g.render();
		Assertions.assertTrue( dot.startsWith( "\n// Routes\ndigraph {" ), dot );
		Assertions.assertTrue( dot.contains( "/home" ) && dot.contains( "AES" ), dot );
		Assertions.assertFalse( dot.contains( "ignored" ), dot );
		Assertions.assertEquals( 3, dot.split( "->", -1 ).length - 1, dot );
	}

}
