package org.openolly.reporting;

public class Event {

	private String rule = null;
	private String capture = null;
	private StackTraceElement[] stack = null;
	
	public Event(String rule, String capture, StackTraceElement[] stack ) {
		this.rule = rule;
		this.capture = capture;
		this.stack = stack;
	}

	public String getRule() {
		return rule;
	}

	public String getCapture() {
		return capture;
	}
	
	public String getCaller( int depth ) {
		return stack[depth].toString();
	}

	public StackTraceElement[] getStack() {
		return stack;
	}
	
	public String getName() {
		if ( capture.indexOf( ':' ) != -1 ) {
			return capture.substring( 0, capture.indexOf(':'));
		} else {
			return capture;
		}
	}
	
	public String getValue() {
		if ( capture.indexOf( ':' ) != -1 ) {
			return capture.substring( capture.indexOf(':') + 1);
		} else {
			return "X";
		}
	}
	
	public String toString() {
		return "[JOT " + rule + "] " + getCaller(2) + " " + getCapture();
	}

}
