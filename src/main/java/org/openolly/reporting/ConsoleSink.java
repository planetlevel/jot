package org.openolly.reporting;

import java.io.PrintStream;
import java.time.Instant;

/**
 * Human readable output. One line per event, plus the caller.
 *
 *   2026-10-15T20:01:02.123Z BLOCKED cve-log4shell-no-exec [[touch, pwned.txt]]
 *       CVE-2021-44228 microsandbox blocked process execution
 *       at java.lang.ProcessBuilder.start(ProcessBuilder.java:1089) ...
 */
public class ConsoleSink implements EventSink {

	private final PrintStream out;

	public ConsoleSink(PrintStream out) {
		this.out = out;
	}

	@Override
	public void accept(Event event) {
		StringBuilder sb = new StringBuilder();
		sb.append( "[JOT] " ).append( Instant.ofEpochMilli( event.getTimestamp() ) ).append( ' ' )
			.append( event.getAction() ).append( ' ' ).append( event.getRule() );
		if ( event.getCapture() != null && !event.getCapture().isEmpty() ) {
			sb.append( ' ' ).append( event.getCapture() );
		}
		if ( event.getMessage() != null ) {
			sb.append( "\n      " ).append( event.getMessage() );
		}
		String caller = event.getCaller( 1 );
		if ( !caller.isEmpty() ) {
			sb.append( "\n      at " ).append( caller );
			String from = event.getCaller( 2 );
			if ( !from.isEmpty() ) sb.append( "\n      from " ).append( from );
		}
		out.println( sb );
	}

	@Override
	public void close() {
		out.flush();
	}

	@Override
	public String toString() {
		return "console";
	}

}
