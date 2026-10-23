package org.openolly.reporting;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Something a sensor observed, or an action a sensor took. Events are immutable once created
 * and are published to the EventBus as they happen.
 */
public class Event implements Comparable<Event> {

	public enum Action {
		/** the sensor captured something */
		OBSERVED,
		/** the sensor would have blocked, but is only monitoring */
		MONITORED,
		/** the sensor blocked the call by throwing an exception */
		BLOCKED
	}

	private static final AtomicInteger counter = new AtomicInteger(0);

	private final String rule;
	private final String capture;
	private final Map<String, Object> data;
	private final StackTraceElement[] stack;
	private final int id;
	private final long timestamp;
	private final Action action;
	private final String message;
	private final String thread;
	private final long threadId;
	private final long trace;
	private final String entry;

	public Event(String rule, String capture, StackTraceElement[] stack) {
		this(rule, capture, stack, Action.OBSERVED, null, null);
	}

	/** An observation with the named values that were captured. capture is the same values as one line of text. */
	public Event(String rule, String capture, StackTraceElement[] stack, Map<String, Object> data) {
		this(rule, capture, stack, Action.OBSERVED, null, data);
	}

	public Event(String rule, String capture, StackTraceElement[] stack, Action action, String message) {
		this(rule, capture, stack, action, message, null);
	}

	/**
	 * data is the captured values by name, each a String, a Number, a Boolean, a list of Strings or null, which is what can go
	 * into JSON, so the event keeps a copy of plain values and nothing of the application's own objects.
	 */
	public Event(String rule, String capture, StackTraceElement[] stack, Action action, String message, Map<String, Object> data) {
		this.rule = rule;
		this.data = data == null || data.isEmpty() ? null : Collections.unmodifiableMap( new LinkedHashMap<String, Object>( data ) );
		this.capture = capture;
		this.stack = stack;
		this.action = action;
		this.message = message;
		this.id = counter.getAndIncrement();
		this.timestamp = System.currentTimeMillis();
		this.thread = Thread.currentThread().getName();
		this.threadId = Thread.currentThread().getId();
		this.trace = Trace.currentId();
		this.entry = Trace.currentEntry();
	}

	public String getRule() {
		return rule;
	}

	public String getCapture() {
		return capture;
	}

	/** The named values the sensor captured, in the order the JOT lists them, or null when it captured none by name. */
	public Map<String, Object> getData() {
		return data;
	}

	public Action getAction() {
		return action;
	}

	/** The sensor's exception message for blocked or monitored events, otherwise null. */
	public String getMessage() {
		return message;
	}

	/** Milliseconds since the epoch. */
	public long getTimestamp() {
		return timestamp;
	}

	public String getThread() {
		return thread;
	}

	public long getThreadId() {
		return threadId;
	}

	/** Identifies the request, or thread, this event was observed in. See Trace. */
	public long getTrace() {
		return trace;
	}

	/** The entry point the event ran under, like com.acme.Calc.add, or null when it happened outside every entry point. */
	public String getEntry() {
		return entry;
	}

	public String getCaller( int depth ) {
		if ( stack == null || depth >= stack.length ) return "";
		return stack[depth].toString();
	}

	/**
	 * The frame of the instrumented method. Frame 0 of an event's stack is Thread.getStackTrace
	 * and frame 1 is the instrumented method itself.
	 */
	public String getCaller() {
		return getCaller( 1 );
	}

	/** The code that called the instrumented method, which is where this event was triggered from. */
	public String getCallSite() {
		return getCaller( 2 );
	}

	public StackTraceElement[] getStack() {
		return stack;
	}

	public String toString() {
		return "[JOT " + rule + "] " + getCallSite() + " " + getCapture();
	}

	public String getHash() {
		return ""+id;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + rule.hashCode() ;
		result = prime * result + capture.hashCode() ;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		if (this == obj)
			return true;
		if (getClass() != obj.getClass())
			return false;
		Event other = (Event) obj;
		return rule.equals(other.rule) && capture.equals(other.capture);
	}

	@Override
	public int compareTo(Event other) {
		if (other == null || this == other)
			return 0;
		return (rule + capture).compareTo( other.rule + other.capture );
	}

}
