package org.openolly;

import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.reporting.Event;
import org.openolly.reporting.Trace;

class TraceTest {

	@Test
	void testIdIsStableUntilStart() {
		long id = Trace.currentId();
		Assertions.assertEquals( id, Trace.currentId() );
		Trace.start();
		Assertions.assertNotEquals( id, Trace.currentId() );
	}

	@Test
	void testEventsRecordTheTraceTheyWereCreatedIn() {
		Trace.start();
		Event a = new Event( "r", "c", null );
		Event b = new Event( "r", "c", null );
		Trace.start();
		Event c = new Event( "r", "c", null );
		Assertions.assertEquals( a.getTrace(), b.getTrace() );
		Assertions.assertNotEquals( a.getTrace(), c.getTrace() );
	}

	@Test
	void testThreadsHaveTheirOwnTrace() throws Exception {
		AtomicLong other = new AtomicLong();
		Thread t = new Thread( () -> other.set( Trace.currentId() ) );
		t.start();
		t.join();
		Assertions.assertNotEquals( Trace.currentId(), other.get() );
	}

}
