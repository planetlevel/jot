package org.openolly.reporting;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Identifies which events belong together. Each thread has a current trace id, and every Event
 * records the id that was current when it was created. A servlet request starts a new id, so
 * everything observed while handling that request shares one. Outside a request the id stays
 * the same for the life of the thread. Sinks use the id to relate events to each other.
 */
public final class Trace {

	private static final AtomicLong counter = new AtomicLong( 10000 );

	private static final ThreadLocal<long[]> current =
		ThreadLocal.withInitial( () -> new long[] { counter.getAndIncrement() } );

	private Trace() {
	}

	/** The id events created on this thread are tagged with. */
	public static long currentId() {
		return current.get()[0];
	}

	/** Begin a new trace on this thread. */
	public static void start() {
		current.get()[0] = counter.getAndIncrement();
	}

	/** End the current trace. A new one begins at the next start. */
	public static void stop() {
		// nothing to release, the id is simply replaced at the next start
	}

}
