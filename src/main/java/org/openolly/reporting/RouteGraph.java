package org.openolly.reporting;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.text.StringEscapeUtils;

import com.google.common.graph.EndpointPair;
import com.google.common.graph.Graphs;
import com.google.common.graph.GraphBuilder;
import com.google.common.graph.MutableGraph;

/**
 * Builds a graph of what happens inside each route, printed to stderr as GraphViz DOT at shutdown.
 *
 * Events from the "rows" sensor start a route. Every other event seen in the same request is
 * chained after the previous one, so each route ends up a path of everything it did. An event
 * from one of the "cols" sensors, such as a forward, starts a new route node and later events
 * continue from there. Requests for static files are ignored.
 *
 * The graph is bounded to maxNodes, anything past that is counted and left out.
 */
public class RouteGraph implements EventSink {

	private static final int DEFAULT_MAX_NODES = 2000;
	private static final int MAX_OPEN_TRACES = 1000;
	private static final String[] STATIC_FILES = { ".js", ".css", ".jpg", ".png", ".gif" };
	// FIXME: HTML Encode specials
	private static final String STYLE = "shape=box, style=\"rounded,filled\",fillcolor=blue,fontcolor=white,fontname=Helvetica,fontsize=10";

	private final MutableGraph<Event> graph = GraphBuilder.directed().allowsSelfLoops( true ).build();
	private final Map<Long, Cursor> traces = new LinkedHashMap<Long, Cursor>( 16, 0.75f, true ) {
		@Override
		protected boolean removeEldestEntry(Map.Entry<Long, Cursor> eldest) {
			return size() > MAX_OPEN_TRACES;
		}
	};

	private final String name;
	private final String route;
	private final List<String> forwards;
	private int maxNodes = DEFAULT_MAX_NODES;
	private long dropped = 0;

	/** Where a request has got to, the route it is in and the last event added to it. */
	private static class Cursor {
		Event route;
		Event tail;
		boolean ignored;
	}

	public RouteGraph( String name, String route, List<String> forwards ) {
		this.name = name;
		this.route = route;
		this.forwards = forwards == null ? new ArrayList<String>() : forwards;
	}

	public RouteGraph maxNodes( int value ) {
		this.maxNodes = value;
		return this;
	}

	@Override
	public synchronized void accept(Event event) {
		Cursor cursor = traces.computeIfAbsent( event.getTrace(), id -> new Cursor() );
		if ( cursor.ignored ) return;

		if ( event.getRule().equalsIgnoreCase( route ) ) {
			if ( isStaticFile( event.getCapture() ) ) {
				cursor.ignored = true;
				return;
			}
			Event node = findExisting( graph.nodes(), event );
			if ( node == event && !room() ) return;
			graph.addNode( node );
			cursor.route = node;
			cursor.tail = node;
		} else if ( cursor.route != null ) {
			Event node = findExisting( Graphs.reachableNodes( graph, cursor.route ), event );
			if ( node == event && !room() ) return;
			graph.putEdge( cursor.tail, node );
			cursor.tail = node;
			if ( isForward( event ) ) cursor.route = node;
		}
	}

	private boolean room() {
		if ( graph.nodes().size() < maxNodes ) return true;
		dropped++;
		return false;
	}

	private boolean isForward(Event event) {
		for ( String forward : forwards ) {
			if ( event.getRule().equalsIgnoreCase( forward ) ) return true;
		}
		return false;
	}

	private static boolean isStaticFile(String capture) {
		for ( String ext : STATIC_FILES ) {
			if ( capture.endsWith( ext ) ) return true;
		}
		return false;
	}

	/** An event already in the graph for the same rule and capture, or the event itself. */
	private static Event findExisting( Set<Event> candidates, Event add ) {
		for ( Event e : candidates ) {
			if ( e.getRule().equals( add.getRule() ) && e.getCapture().equals( add.getCapture() ) ) return e;
		}
		return add;
	}

	@Override
	public synchronized void close() {
		String out = render();
		if ( !out.isEmpty() ) System.err.print( out );
	}

	/** The graph as GraphViz DOT, or an empty string if nothing has been recorded. */
	public synchronized String render() {
		if ( graph.nodes().isEmpty() ) return "";
		Map<Event, Integer> ids = new HashMap<Event, Integer>();
		for ( Event e : graph.nodes() ) ids.put( e, ids.size() );

		StringBuilder out = new StringBuilder( "\n// " + name + "\ndigraph {\n" );
		out.append( "\t{ node [" + STYLE + "]\n" );
		for ( Event e : graph.nodes() ) {
			out.append( "\t\t" + ids.get( e ) + " [label=<<TABLE border=\"0\">"
				+ "<TR><TD>" + StringEscapeUtils.escapeHtml4( e.getRule() ) + "</TD></TR>"
				+ "<TR><TD>" + StringEscapeUtils.escapeHtml4( e.getCapture() ) + "</TD></TR>"
				+ "<TR><TD>" + StringEscapeUtils.escapeHtml4( e.getCallSite() ) + "</TD></TR>"
				+ "</TABLE>>];\n" );
		}
		out.append( "\t}\n\t{ edge [style=dashed]\n" );
		for ( EndpointPair<Event> edge : graph.edges() ) {
			out.append( "\t\t" + ids.get( edge.source() ) + " -> " + ids.get( edge.target() ) + "\n" );
		}
		out.append( "\t}\n}\n" );
		if ( dropped > 0 ) out.append( "// " + dropped + " events not shown, this graph is limited to " + maxNodes + " nodes\n" );
		return out.toString();
	}

	@Override
	public String toString() {
		return "RouteGraph " + name;
	}

}
