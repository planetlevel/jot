package org.openolly.reporting;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.time.Instant;

/**
 * One JSON object per line, for machines.
 *
 *   {"time":"2026-10-15T20:01:02.123Z","id":4,"sensor":"x","action":"blocked","capture":"...",
 *    "message":"...","thread":"main","caller":"...","stack":["...","..."]}
 *
 * The stack is only included for blocked and monitored events, and is limited to 15 frames.
 */
public class JsonSink implements EventSink {

	private static final int MAX_FRAMES = 15;

	private final Writer out;
	private final String name;

	public JsonSink(String path) {
		this.name = "json:" + path;
		try {
			this.out = new BufferedWriter( new FileWriter( path, true ) );
		} catch ( IOException e ) {
			throw new IllegalArgumentException( "Can't write jot.output.file " + path + ": " + e.getMessage(), e );
		}
	}

	public JsonSink(Writer out) {
		this.name = "json";
		this.out = out;
	}

	@Override
	public void accept(Event event) {
		try {
			out.write( toJson( event ) );
			out.write( '\n' );
			out.flush();
		} catch ( IOException e ) {
			throw new RuntimeException( e );
		}
	}

	static String toJson(Event event) {
		StringBuilder sb = new StringBuilder( 256 );
		sb.append( "{\"time\":" );
		quote( sb, Instant.ofEpochMilli( event.getTimestamp() ).toString() );
		sb.append( ",\"id\":" ).append( event.getHash() );
		sb.append( ",\"sensor\":" );
		quote( sb, event.getRule() );
		sb.append( ",\"action\":" );
		quote( sb, event.getAction().name().toLowerCase() );
		sb.append( ",\"capture\":" );
		quote( sb, event.getCapture() );
		if ( event.getMessage() != null ) {
			sb.append( ",\"message\":" );
			quote( sb, event.getMessage() );
		}
		sb.append( ",\"thread\":" );
		quote( sb, event.getThread() );
		String caller = event.getCaller( 1 );
		if ( !caller.isEmpty() ) {
			sb.append( ",\"caller\":" );
			quote( sb, caller );
		}
		StackTraceElement[] stack = event.getStack();
		if ( event.getAction() != Event.Action.OBSERVED && stack != null ) {
			sb.append( ",\"stack\":[" );
			int end = Math.min( stack.length, MAX_FRAMES + 1 );
			for ( int i = 1; i < end; i++ ) {
				if ( i > 1 ) sb.append( ',' );
				quote( sb, stack[i].toString() );
			}
			sb.append( ']' );
		}
		return sb.append( '}' ).toString();
	}

	private static void quote(StringBuilder sb, String s) {
		if ( s == null ) {
			sb.append( "null" );
			return;
		}
		sb.append( '"' );
		for ( int i = 0; i < s.length(); i++ ) {
			char c = s.charAt( i );
			switch ( c ) {
			case '"': sb.append( "\\\"" ); break;
			case '\\': sb.append( "\\\\" ); break;
			case '\n': sb.append( "\\n" ); break;
			case '\r': sb.append( "\\r" ); break;
			case '\t': sb.append( "\\t" ); break;
			default:
				if ( c < 0x20 ) sb.append( String.format( "\\u%04x", (int) c ) );
				else sb.append( c );
			}
		}
		sb.append( '"' );
	}

	@Override
	public void close() {
		try {
			out.close();
		} catch ( IOException e ) {
			// nothing useful to do at shutdown
		}
	}

	@Override
	public String toString() {
		return name;
	}

}
