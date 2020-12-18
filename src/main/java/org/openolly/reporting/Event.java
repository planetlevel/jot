package org.openolly.reporting;

public class Event implements Comparable {

	private String rule = null;
	private String capture = null;
	private StackTraceElement[] stack = null;
	private int id = 0;
	private static int counter = 0;
	
	public Event(String rule, String capture, StackTraceElement[] stack ) {
		this.rule = rule;
		this.capture = capture;
		this.stack = stack;
		this.id = counter++;
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
	
	// FIXME: return the "name" of a name-value pair captured. Needs update.
	public String getNameFromCapture() {
		if ( capture.indexOf( ':' ) != -1 ) {
			return capture.substring( 0, capture.indexOf(':'));
		} else {
			return capture;
		}
	}
	
	// FIXME: return the "name" of a name-value pair captured. Needs update.
	public String getValueFromCapture() {
		if ( capture.indexOf( ':' ) != -1 ) {
			return capture.substring( capture.indexOf(':') + 1);
		} else {
			return "X";
		}
	}
	
	public String toString() {
		return "[JOT " + rule + "] " + getCaller(2) + " " + getCapture();
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
		return (rule == other.rule && capture == other.capture );
	}

	@Override
	public int compareTo(Object obj) {
		if (obj == null)
			return 0;       
		if (this == obj)
			return 0;
		if (getClass() != obj.getClass())
			return 0;
		Event other = (Event) obj;
		return (rule + capture).compareTo( other.rule + other.capture );
	}


}
