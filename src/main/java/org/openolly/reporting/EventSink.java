package org.openolly.reporting;

/**
 * Receives events from the EventBus. Sinks are called one at a time from a single
 * background thread, so they don't need to be thread safe or fast.
 */
public interface EventSink {

	void accept(Event event);

	/** Called once at shutdown, after the last event has been delivered. */
	default void close() {
	}

}
