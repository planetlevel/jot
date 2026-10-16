package org.openolly.reporting;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.InetAddress;
import java.time.Instant;
import java.util.UUID;

/**
 * One JSON object per line, for machines. Every line is flat and carries everything known about
 * the event, so the log can be loaded into a database with no further context.
 *
 *   v          format version, currently 1
 *   time, ts   when the event happened, as ISO 8601 and as epoch milliseconds
 *   run        random id for this JVM run, with host and pid it identifies the process
 *   host, pid, app   where the event came from. app is jot.app, or else the main class
 *   id         event number, unique within a run
 *   trace      events with the same trace came from the same request, or thread outside a request
 *   thread, thread_id
 *   sensor, action (observed, monitored or blocked), capture, message (blocks only)
 *   method     the instrumented method, for example javax.crypto.Cipher.getInstance
 *   call_site  the code that called it, for example com.acme.Ticket.encrypt(Ticket.java:125)
 *   stack      frames starting at the instrumented method, up to jot.output.stack, default 25
 */
public class JsonSink implements EventSink {

	private static final int DEFAULT_FRAMES = 25;

	private final Writer out;
	private final String name;
	private final int maxFrames;
	private final String origin;

	public JsonSink(String path) {
		this.name = "json:" + path;
		this.maxFrames = Integer.getInteger( "jot.output.stack", DEFAULT_FRAMES );
		this.origin = origin();
		try {
			this.out = new BufferedWriter( new FileWriter( path, true ) );
		} catch ( IOException e ) {
			throw new IllegalArgumentException( "Can't write jot.output.file " + path + ": " + e.getMessage(), e );
		}
	}

	public JsonSink(Writer out) {
		this( out, DEFAULT_FRAMES );
	}

	public JsonSink(Writer out, int maxFrames) {
		this.name = "json";
		this.out = out;
		this.maxFrames = maxFrames;
		this.origin = origin();
	}

	/** The fields that are the same for every event from this JVM, as the middle of a JSON object. */
	private static String origin() {
		StringBuilder sb = new StringBuilder();
		sb.append( ",\"run\":" );
		quote( sb, RUN );
		sb.append( ",\"host\":" );
		quote( sb, hostName() );
		sb.append( ",\"pid\":" ).append( ProcessHandle.current().pid() );
		sb.append( ",\"app\":" );
		quote( sb, appName() );
		return sb.toString();
	}

	private static final String RUN = UUID.randomUUID().toString().substring( 0, 8 );

	private static String hostName() {
		String host = System.getProperty( "jot.host", System.getenv( "HOSTNAME" ) );
		if ( host != null && !host.isEmpty() ) return host;
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch ( Exception e ) {
			return "unknown";
		}
	}

	private static String appName() {
		String app = System.getProperty( "jot.app" );
		if ( app == null || app.isEmpty() ) {
			app = System.getProperty( "sun.java.command", "unknown" ).split( " " )[0];
		}
		return app;
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

	String toJson(Event event) {
		StringBuilder sb = new StringBuilder( 512 );
		sb.append( "{\"v\":1,\"time\":" );
		quote( sb, Instant.ofEpochMilli( event.getTimestamp() ).toString() );
		sb.append( ",\"ts\":" ).append( event.getTimestamp() );
		sb.append( origin );
		sb.append( ",\"id\":" ).append( event.getHash() );
		sb.append( ",\"trace\":" ).append( event.getTrace() );
		sb.append( ",\"thread\":" );
		quote( sb, event.getThread() );
		sb.append( ",\"thread_id\":" ).append( event.getThreadId() );
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
		String method = event.getCaller( 1 );
		if ( !method.isEmpty() ) {
			sb.append( ",\"method\":" );
			quote( sb, method );
		}
		String callSite = event.getCallSite();
		if ( !callSite.isEmpty() ) {
			sb.append( ",\"call_site\":" );
			quote( sb, callSite );
		}
		StackTraceElement[] stack = event.getStack();
		if ( maxFrames > 0 && stack != null && stack.length > 1 ) {
			sb.append( ",\"stack\":[" );
			int end = Math.min( stack.length, maxFrames + 1 );
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
