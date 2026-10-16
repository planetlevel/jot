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
 * There are three styles.
 *   list     one row per call site, one column for the "cols" sensor, holding what it captured
 *   compare  rows from the "rows" sensor, columns named by the "cols" sensor's captures
 *   table    rows from the "rows" sensor, one column per "cols" sensor, holding what it captured
 *
 * compare and table relate a row to a column when both were observed in the same request, so
 * "rows" is typically a sensor that identifies the route.
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
	private String data = null;
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
			set( event.getCallSite(), cols[0], shorten( event.getCapture() ) );
		}
	}

	private void acceptRelated(Event event) {
		boolean isRow = matches( event, rows );
		String column = null;
		String value = null;
		for ( String col : cols ) {
			if ( matches( event, col ) ) {
				if ( mode == ReportStyle.COMPARE ) {
					column = event.getNameFromCapture();
					value = event.getValueFromCapture();
				} else {
					column = col;
					value = event.getCapture();
				}
				break;
			}
		}
		if ( !isRow && column == null ) return;

		Window trace = traces.computeIfAbsent( event.getTrace(), id -> new Window() );
		if ( isRow ) {
			String row = event.getNameFromCapture();
			if ( trace.rowNames.size() < MAX_PER_TRACE && trace.rowNames.add( row ) ) {
				for ( String[] cell : trace.cells ) set( row, cell[0], cell[1] );
			}
		}
		if ( column != null && trace.cells.size() < MAX_PER_TRACE ) {
			String shortened = shorten( value );
			trace.cells.add( new String[] { column, shortened } );
			for ( String row : trace.rowNames ) set( row, column, shortened );
		}
	}

	private static boolean matches(Event event, String rule) {
		return rule != null && event.getRule().equalsIgnoreCase( rule );
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

	public Report data( String value ) {
		this.data = value;
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
