package com.contrastsecurity;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.reporting.Event;
import org.openolly.reporting.Report;
import org.openolly.reporting.Trace;

class TableTest {

	@Test
	void testTable() {
		Trace trace = new Trace();
		StackTraceElement[] stack = Thread.currentThread().getStackTrace();
		trace.addEvent( new Event("rule1", "/route1", stack) );
		trace.addEvent( new Event("rule2", "RoleA:value", stack) );
		trace.addEvent( new Event("rule2", "RoleB:value", stack) );
		trace.addEvent( new Event("rule2", "RoleD:value", stack) );
		trace.addEvent( new Event("rule2", "RoleE:value", stack) );
		System.out.println( "TRACE: " + trace );
		Report t = new Report()
				.name("Test Report")
				.type("compare")
				.rows("rule1")
				.cols("rule2");
		t.update( trace );
		Assertions.assertEquals("[value]", t.get("/route1", "RoleA").toString() );
	}

	@Test
	void testList() {
		Trace trace = new Trace();
		StackTraceElement[] stack = Thread.currentThread().getStackTrace();
		trace.addEvent( new Event("rule1", "/route1", stack) );
		trace.addEvent( new Event("rule2", "DES", stack) );
		trace.addEvent( new Event("rule2", "AES", stack) );
		trace.addEvent( new Event("rule2", "CBC", stack) );
		trace.addEvent( new Event("rule2", "MD5", stack) );
		System.out.println( "TRACE: " + trace );
		Report t = new Report()
				.name("Test Report")
				.type("list")
				.cols("rule2");
		t.update( trace );
		t.dump();
		String caller = stack[2].toString();
		Assertions.assertEquals("[AES, CBC, DES, MD5]", t.get(caller, "rule2").toString() );
	}

	
}

