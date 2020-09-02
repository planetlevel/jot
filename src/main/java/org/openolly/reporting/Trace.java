package org.openolly.reporting;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class Trace {

	private static AtomicInteger counter = new AtomicInteger(10000);
    
    private static final ThreadLocal<Trace> currentTrace =
        new ThreadLocal<Trace>() {
            @Override protected Trace initialValue() {
                return new Trace();
        }
    };

    private final int traceId = counter.getAndIncrement();
	private List<Event> events = new ArrayList<Event>();
		
	public Trace() {
	}
	
	public static Trace getCurrentTrace() {
		return currentTrace.get();
	}
	
	public int getId() {
		return traceId;
	}

	public void addEvent(Event event) {
		events.add( event );
	}

	public void start() {
		events.clear();
	}
	
	public void stop() {
		if ( events.isEmpty() ) return;
		printTrace();
		Reporter.update( this );
	}
	
	public void printTrace() {
		if ( events.isEmpty() ) return;
		System.out.println( "\n"+toString());
		for ( Event event : events ) {
			System.out.println( "  " + event );
		}
		System.out.println();
	}

	public List<Event> getEventsForRule(String rulename) {
		List<Event> list = new ArrayList<Event>();
		for( Event e : events ) {
			if ( e.getRule().equalsIgnoreCase(rulename) ) {
				list.add(e);
			}
		}
		return list;
	}

	public String toString() {
		return "TRACE-" + traceId + "(" + events.size() +")";
	}

	public int getSize() {
		return events.size();
	}
	
}
