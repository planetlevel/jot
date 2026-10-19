package org.openolly.reporting;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.TreeBasedTable;

/**
 * Summarizes the events it receives as a table, which is printed to stderr at shutdown.
 *
 * What a report reads is written sensor.field, the field of a sensor's captures, like http-route.path. A bare sensor
 * name is what it captured as one line.
 *
 * There are three styles.
 *   list     one row per call site, one column for the "cols" field, holding what it captured
 *   table    rows from the "rows" field, one column per "cols" field, holding what it captured
 *   compare  rows from the "rows" field, a column for each value of the "cols" field, holding the "value" field of the same
 *            sensor, or an x when there is none
 *
 * compare and table relate a row to a column when both were observed in the same request, so
 * "rows" is typically a field that identifies the route.
 *
 * Reports are bounded. A table holds at most maxRows rows and each cell holds at most
 * maxValues values. Anything past that is counted and not stored.
 */
public class Report implements EventSink {

	public enum ReportStyle {
		LIST, COMPARE, TABLE
	}

	private static final int DEFAULT_MAX_ROWS = 1000;
	private static final int DEFAULT_MAX_VALUES = 20;
	/** requests tracked at once, the least recently active is forgotten first */
	private static final int MAX_OPEN_TRACES = 1000;
	/** rows and cells remembered for one request */
	private static final int MAX_PER_TRACE = 200;

	private final TreeBasedTable<String, String, Set<String>> table = TreeBasedTable.create();
	private final Map<Long, Window> traces = new LinkedHashMap<Long, Window>( 16, 0.75f, true ) {
		@Override
		protected boolean removeEldestEntry(Map.Entry<Long, Window> eldest) {
			return size() > MAX_OPEN_TRACES;
		}
	};

	private ReportStyle mode = null;
	private String name = null;
	private String rows = null;
	private String[] cols = null;
	private String value = null;
	private int maxRows = DEFAULT_MAX_ROWS;
	private int maxValues = DEFAULT_MAX_VALUES;
	private int rowNameColWidth = 10;
	private long dropped = 0;

	/** What one request has shown so far, so a row and a column seen at different times still meet. */
	private static class Window {
		final Set<String> rowNames = new LinkedHashSet<String>();
		final List<String[]> cells = new ArrayList<String[]>();
	}

	@Override
	public synchronized void accept(Event event) {
		if ( mode == null ) return;
		switch ( mode ) {
		case LIST: acceptList( event ); break;
		case COMPARE:
		case TABLE: acceptRelated( event ); break;
		}
	}

	private void acceptList(Event event) {
		if ( matches( event, cols[0] ) ) {
			for ( String v : values( event, cols[0] ) ) set( event.getCallSite(), cols[0], shorten( v ) );
		}
	}

	private void acceptRelated(Event event) {
		List<String> rowValues = matches( event, rows ) ? values( event, rows ) : List.of();
		String column = null;
		List<String> cells = List.of();
		for ( String col : cols ) {
			if ( matches( event, col ) ) {
				if ( mode == ReportStyle.COMPARE ) {
					cells = new ArrayList<String>();
					List<String> marks = value == null ? List.of() : values( event, value );
					for ( String name : values( event, col ) ) cells.add( name + "\u0000" + ( marks.isEmpty() ? "x" : String.join( ",", marks ) ) );
				} else {
					column = col;
					cells = values( event, col );
				}
				break;
			}
		}
		if ( rowValues.isEmpty() && cells.isEmpty() ) return;

		Window trace = traces.computeIfAbsent( event.getTrace(), id -> new Window() );
		for ( String row : rowValues ) {
			if ( trace.rowNames.size() < MAX_PER_TRACE && trace.rowNames.add( row ) ) {
				for ( String[] cell : trace.cells ) set( row, cell[0], cell[1] );
			}
		}
		for ( String cell : cells ) {
			String name = column;
			String shortened;
			if ( mode == ReportStyle.COMPARE ) {
				int split = cell.indexOf( '\u0000' );
				name = cell.substring( 0, split );
				shortened = shorten( cell.substring( split + 1 ) );
			} else {
				shortened = shorten( cell );
			}
			if ( trace.cells.size() >= MAX_PER_TRACE ) break;
			trace.cells.add( new String[] { name, shortened } );
			for ( String row : trace.rowNames ) set( row, name, shortened );
		}
	}

	/** True if the reference, sensor or sensor.field, is to this event's sensor. */
	private static boolean matches(Event event, String ref) {
		return ref != null && event.getRule().equalsIgnoreCase( sensorOf( ref ) );
	}

	static String sensorOf(String ref) {
		int dot = ref.indexOf( '.' );
		return dot < 0 ? ref : ref.substring( 0, dot );
	}

	/** What the event holds for the reference, one value per item of a list. A bare sensor name is the one line it captured. */
	static List<String> values(Event event, String ref) {
		int dot = ref.indexOf( '.' );
		if ( dot < 0 ) return List.of( event.getCapture() );
		Object found = event.getData() == null ? null : event.getData().get( ref.substring( dot + 1 ) );
		if ( found == null ) return List.of();
		List<String> out = new ArrayList<String>();
		if ( found instanceof List ) {
			for ( Object item : (List<?>)found ) out.add( String.valueOf( item ) );
		} else {
			out.add( String.valueOf( found ) );
		}
		return out;
	}

	private static String shorten(String value) {
		return StringUtils.abbreviateMiddle( value, "...", 50 );
	}

	//====================================

	public Report name( String value ) {
		this.name = value;
		rowNameColWidth = Math.max( rowNameColWidth, name.length() + 4 );
		return this;
	}

	public Report type( String value ) {
		try {
			this.mode = ReportStyle.valueOf( value.trim().toUpperCase() );
		} catch ( IllegalArgumentException | NullPointerException e ) {
			throw new IllegalArgumentException( "unknown report type '" + value + "', use list, compare or table" );
		}
		return this;
	}

	public Report rows( String value ) {
		this.rows = value;
		return this;
	}

	public Report cols( String value ) {
		this.cols = value == null ? null : value.split( ",\\s*" );
		return this;
	}

	/** compare only, the field that fills the cells. */
	public Report value( String value ) {
		this.value = value;
		return this;
	}

	public Report maxRows( int value ) {
		this.maxRows = value;
		return this;
	}

	public Report maxValues( int value ) {
		this.maxValues = value;
		return this;
	}

	/** Throws if the report is missing what its type needs. */
	public Report validate() {
		if ( name == null || mode == null ) throw new IllegalArgumentException( "a report needs a name and a type" );
		if ( cols == null || cols.length == 0 ) throw new IllegalArgumentException( "report '" + name + "' needs cols" );
		if ( mode != ReportStyle.LIST && StringUtils.isBlank( rows ) ) {
			throw new IllegalArgumentException( "report '" + name + "' needs rows" );
		}
		if ( value != null && ( mode != ReportStyle.COMPARE || !sensorOf( value ).equalsIgnoreCase( sensorOf( cols[0] ) ) ) ) {
			throw new IllegalArgumentException( "report '" + name + "' value only goes with compare, and is a field of the cols sensor" );
		}
		return this;
	}

	//====================================

	public synchronized Set<String> get( String r, String c ) {
		return table.get( r, c );
	}

	public synchronized void set( String r, String c, String v ) {
		if ( StringUtils.isEmpty( r ) || StringUtils.isEmpty( c ) || StringUtils.isEmpty( v ) ) return;
		Set<String> current = table.get( r, c );
		if ( current == null ) {
			if ( !table.containsRow( r ) && table.rowKeySet().size() >= maxRows ) {
				dropped++;
				return;
			}
			current = new TreeSet<String>();
			table.put( r, c, current );
		}
		if ( current.size() < maxValues ) {
			current.add( v );
		} else if ( !current.contains( v ) ) {
			dropped++;
		}
		rowNameColWidth = Math.max( rowNameColWidth, r.length() );
	}

	/** Print the table. Nothing is printed for a report that saw no events. */
	@Override
	public synchronized void close() {
		String out = render();
		if ( !out.isEmpty() ) System.err.print( out );
	}

	/** The table as text, or an empty string if nothing has been recorded. */
	public synchronized String render() {
		if ( table.isEmpty() ) return "";
		StringBuilder out = new StringBuilder( "\n" );
		out.append( StringUtils.rightPad( name, rowNameColWidth ) ).append( ' ' );
		for ( String col : table.columnKeySet() ) {
			out.append( StringUtils.rightPad( col, getMaxWidth( col ) ) ).append( ' ' );
		}
		out.append( '\n' ).append( StringUtils.repeat( '-', rowNameColWidth ) ).append( ' ' );
		for ( String col : table.columnKeySet() ) {
			out.append( StringUtils.repeat( '-', getMaxWidth( col ) ) ).append( ' ' );
		}
		out.append( '\n' );

		for ( String row : table.rowKeySet() ) {
			out.append( StringUtils.rightPad( row, rowNameColWidth ).substring( 0, rowNameColWidth ) ).append( ' ' );
			for ( String col : table.columnKeySet() ) {
				Set<String> values = table.get( row, col );
				String value = values == null ? "" : String.join( ",", values );
				out.append( StringUtils.rightPad( value, getMaxWidth( col ) ) ).append( ' ' );
			}
			out.append( '\n' );
		}
		if ( dropped > 0 ) {
			out.append( "(" + dropped + " entries not shown, this report is limited to " + maxRows + " rows of "
				+ maxValues + " values per cell)\n" );
		}
		return out.append( '\n' ).toString();
	}

	private int getMaxWidth( String col ) {
		int width = Math.max( 4, col.length() );
		for ( String row : table.rowKeySet() ) {
			Set<String> values = table.get( row, col );
			if ( values != null ) width = Math.max( width, String.join( ",", values ).length() );
		}
		return width;
	}

	@Override
	public String toString() {
		return "Report " + name;
	}
}
