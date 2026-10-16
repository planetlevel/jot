package org.openolly.reporting;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Delivers events to sinks on a background thread, so the application's threads never format
 * or write output. The queue is bounded. If sinks can't keep up, new events are dropped and
 * counted instead of slowing the application down.
 *
 * With no sinks configured, publishing does nothing.
 *
 * Options, as system properties
 *   jot.output        comma separated sinks, "console" and/or "json". Default "console".
 *   jot.output.file   file for the json sink. Default "jot-events.jsonl".
 *   jot.events        "all" (default) or "violations" to only send monitored and blocked events
 *                     to the console and json sinks. Reports always see every event.
 *   jot.queue.size    events to buffer. Default 10000.
 */
public final class EventBus {

	private static final int DEFAULT_QUEUE_SIZE = 10000;

	private static volatile boolean active = false;
	private static int queueSize = DEFAULT_QUEUE_SIZE;
	private static BlockingQueue<Event> queue;
	private static final List<EventSink> sinks = new CopyOnWriteArrayList<EventSink>();
	private static Thread worker;
	private static volatile boolean running = false;
	private static final AtomicLong dropped = new AtomicLong();
	private static boolean hookInstalled = false;

	private EventBus() {
	}

	/** Configure from -Djot.* system properties and start delivering. */
	public static synchronized void configureFromSystemProperties() {
		List<EventSink> list = new ArrayList<EventSink>();
		String outputs = System.getProperty( "jot.output", "console" );
		for ( String name : outputs.split( "," ) ) {
			switch ( name.trim().toLowerCase() ) {
			case "console": list.add( new ConsoleSink( System.err ) ); break;
			case "json": list.add( new JsonSink( System.getProperty( "jot.output.file", "jot-events.jsonl" ) ) ); break;
			case "": break;
			default: System.err.println( "[JOT] Unknown jot.output '" + name.trim() + "', ignoring. Use console or json." );
			}
		}
		if ( System.getProperty( "jot.events", "all" ).equalsIgnoreCase( "violations" ) ) {
			List<EventSink> filtered = new ArrayList<EventSink>();
			for ( EventSink sink : list ) filtered.add( new ViolationsOnlySink( sink ) );
			list = filtered;
		}
		configure( list, Integer.getInteger( "jot.queue.size", DEFAULT_QUEUE_SIZE ) );

		if ( !hookInstalled ) {
			hookInstalled = true;
			Runtime.getRuntime().addShutdownHook( new Thread( EventBus::shutdown, "jot-events-shutdown" ) );
		}
	}

	/** Replace all sinks and start delivering. */
	public static synchronized void configure( List<EventSink> newSinks, int size ) {
		shutdown();
		sinks.addAll( newSinks );
		queueSize = Math.max( size, 1 );
		dropped.set( 0 );
		if ( !sinks.isEmpty() ) start();
	}

	/** Add a sink, such as a report, starting delivery if it isn't running. */
	public static synchronized void addSink( EventSink sink ) {
		sinks.add( sink );
		if ( !active ) start();
	}

	private static void start() {
		queue = new ArrayBlockingQueue<Event>( queueSize );
		running = true;
		worker = new Thread( EventBus::run, "jot-events" );
		worker.setDaemon( true );
		worker.start();
		active = true;
	}

	public static void publish(Event event) {
		if ( !active ) return;
		if ( !queue.offer( event ) ) dropped.incrementAndGet();
	}

	/** Number of events dropped because the queue was full. */
	public static long getDropped() {
		return dropped.get();
	}

	/** Deliver everything still queued, then close the sinks. */
	public static synchronized void shutdown() {
		if ( !active ) return;
		active = false;
		running = false;
		try {
			worker.join( 2000 );
		} catch ( InterruptedException e ) {
			Thread.currentThread().interrupt();
		}
		drain();
		PrintStream err = System.err;
		if ( dropped.get() > 0 ) err.println( "[JOT] " + dropped.get() + " events were dropped because the event queue was full. Raise jot.queue.size." );
		for ( EventSink sink : sinks ) {
			try {
				sink.close();
			} catch ( Throwable t ) {
				err.println( "[JOT] Error closing " + sink + ": " + t );
			}
		}
		sinks.clear();
	}

	private static void run() {
		while ( running ) {
			try {
				Event event = queue.poll( 100, TimeUnit.MILLISECONDS );
				if ( event != null ) deliver( event );
			} catch ( InterruptedException e ) {
				return;
			}
		}
	}

	private static void drain() {
		Event event;
		while ( ( event = queue.poll() ) != null ) deliver( event );
	}

	private static void deliver(Event event) {
		for ( EventSink sink : sinks ) {
			try {
				sink.accept( event );
			} catch ( Throwable t ) {
				// a broken sink must never affect the others or the application
				System.err.println( "[JOT] Error in " + sink + ": " + t );
			}
		}
	}

}
