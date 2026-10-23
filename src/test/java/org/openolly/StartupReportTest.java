package org.openolly;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.config.StartupReport;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

class StartupReportTest {

	@Test
	void sayWhatTheAgentStartedWith() {
		List<String> said = new CopyOnWriteArrayList<>();
		List<EventSink> sinks = new ArrayList<>();
		sinks.add( new EventSink() {
			public void accept( Event e ) {
				if ( "jot-config".equals( e.getRule() ) ) said.add( e.getCapture() );
			}
		} );
		EventBus.configure( sinks, 100 );
		String control = System.getProperty( "jot.control" );
		System.setProperty( "jot.control", "/tmp/control.yaml" );
		try {
			StartupReport.publish( "/x/jot.yaml" );
			EventBus.shutdown();
		} finally {
			if ( control == null ) System.clearProperty( "jot.control" ); else System.setProperty( "jot.control", control );
		}
		Assertions.assertTrue( said.contains( "lock=none" ), said.toString() );
		Assertions.assertTrue( said.contains( "jots=/x/jot.yaml" ), said.toString() );
		Assertions.assertTrue( said.contains( "control=/tmp/control.yaml" ), said.toString() );
	}
}
