package org.openolly.reporting;

import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.TreeBasedTable;

public class Report {

	private int rowNameColWidth = 10;
	
	private TreeBasedTable<String, String, Set<String>> table = TreeBasedTable.create();
	private ReportStyle mode = null;
	private String name = null;
	private String rows = null;
	private String[] cols = null;
	private String data = null;
	
	public enum ReportStyle {
		LIST, COMPARE, TABLE, SERIES
	}
	
	public Report() {
		Reporter.add( this );
	}

	public void update( Trace t ) {
		try {			
			switch( mode ) {
			case LIST: updateList( t ); break;
			case COMPARE: updateCompare( t ); break;
			case TABLE: updateTable( t ); break;
			case SERIES: updateSeries( t ); break;
			}
		}catch( Exception e ) {
			e.printStackTrace();
		}
	}
	
	private void updateList(Trace t) {
		for( Event colEvent : t.getEventsForRule( cols[0] ) ) {
			String rowName = colEvent.getCaller(2);
			String colName = cols[0]; 
			String data = colEvent.getCapture();
			String shortened = StringUtils.abbreviateMiddle(data, "...", 50 );
			set( rowName, colName, shortened );
		}
	}

	private void updateCompare(Trace t) {
		for (Event rowEvent : t.getEventsForRule( rows ) ) {
			String rowName = rowEvent.getName(); 
			for( Event colEvent : t.getEventsForRule( cols[0] ) ) {
				String colName = colEvent.getName(); 
				String data = colEvent.getValue();    // FIXME: get rid of getValue() use getCapture()
				String shortened = StringUtils.abbreviateMiddle(data, "...", 50 );
				set( rowName, colName, shortened );
			}
		}
	}

	private void updateTable(Trace t) {
		for (Event rowEvent : t.getEventsForRule( rows ) ) {
			String r = rowEvent.getName(); 
			for ( String col : cols ) {
				for (Event event : t.getEventsForRule( col ) ) {
					String data = event.getCapture();
					String shortened = StringUtils.abbreviateMiddle(data, "...", 50 );
					set( r, col, shortened );
				}
			}
		}
	}

	
    private final static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static int counter = 10000;
    
    // FIXME: Should date be in Events, or just added here in Table?
	private void updateSeries(Trace t) {
		String time = dateFormat.format(new Date());
		for (Event rowEvent : t.getEventsForRule( rows ) ) {
			String r = rowEvent.getName(); 
			for ( String col : cols ) {
				String[] parts = col.split(":");
				int frame = -1;
				if ( parts.length > 1 ) {
					col = parts[0];
					frame = Integer.parseInt( parts[1] );
				}
				for ( Event event : t.getEventsForRule( col ) ) {
					StackTraceElement[] stack = event.getStack();
					String caller = "";
					if ( frame != -1 ) {
						caller = stack[frame].toString();
					}
					String row = "" + counter++;
					String item = event.getCapture();
					// set( row, " Time", time );    // extra space so this will sort first
					set( row, rows, r );
					set( row, "Method Call", caller );
					set( row, col, item );
				}
			}
		}
	}


	private void dumpStack(StackTraceElement[] stack) {
		for ( StackTraceElement frame : stack ) {
			System.out.println( "    " + frame );
		}
	}

//====================================	
	
	public Report name( String value ) {
		this.name = value;
		rowNameColWidth = Math.max( rowNameColWidth, name.length() + 4 );
		return this;
	}
	
	public Report type( String value ) {
		this.mode = ReportStyle.valueOf( value.toUpperCase() );
		return this;
	}
	
	
	// FIXME: check to be sure value is a legit rule name
	
	public Report rows( String value ) {
		this.rows = value;
		return this;
	}
	
	// FIXME: check to be sure value is a legit rule name
	
	public Report cols( String value ) {
		this.cols = value.split(", ");
		return this;
	}
	
	// FIXME: check to be sure value is a legit rule name
	
	public Report data( String value ) {
		this.data = value;
		return this;
	}
	
//====================================	
	
	public void set( String r, String c, Collection<String> values ) {
		for ( String v : values )  {
			set( r, c, v );
		}
	}
	
	public Set<String> get( String r, String c ) {
		return table.get(r, c);
	}
	
	public void set( String r, String c, String v ) {
		if ( r != null && !r.isEmpty() && 
			 c != null && !c.isEmpty() &&
			 v != null && !v.isEmpty() ) {
			Set<String> current = table.get( r,  c );
			if ( current == null ) {
				current = new TreeSet<String>();
				table.put( r, c, current);
			}
			current.add( v );
			rowNameColWidth = Math.max( rowNameColWidth, r.length() );
		} else {
			System.err.println( "Failed attempt to set " + r + ", " + c + ", " + v );
		}
	}
	
	public void clear( String r, String c ) {
		table.remove( r, c );
	}
	
	public void addRow( String r ) {
		if ( r != null && !r.isEmpty() ) {
			set( r, "|||", "X" );
		}
	}
	
	
	public void addCol( String c ) {
		if ( c != null && !c.isEmpty() ) {
			set( "|||", c, "X" );
		}
	}
	
	public void clearRow( String r ) {
		for( String c : table.columnKeySet() ) {
			table.remove( r, c );
		}
	}
	
	public void clearCol( String c ) {
		for ( String r : table.rowKeySet() ) {
			table.remove( r, c );
		}
	}
	
	public synchronized void dump() {
		
		// print headers
		System.err.print( StringUtils.rightPad(name, rowNameColWidth) );
		System.err.print( " " );
		for ( String col : table.columnKeySet() )  {
			if ( !col.contentEquals( "|||" ) ) {
				int colWidth = getMaxWidth( col );
				System.err.print( StringUtils.rightPad(col, colWidth, " ") );
				System.err.print( " " );
			}
		}		
		
		// print ---- 
		System.err.println();
		String under1 = StringUtils.repeat( "-", rowNameColWidth );
		System.err.print( under1 );
		System.err.print( " " );
		for ( String col : table.columnKeySet() ) {
			if ( !col.equals("|||" ) ) {
				int colWidth = getMaxWidth( col );
				String under2 = StringUtils.repeat( "-", colWidth );
				System.err.print( under2 );
				System.err.print( " " );
			}
		}
		System.err.println();
		
		// print data
		for ( String row : table.rowKeySet() ) {
			if ( !row.equals( "|||" ) ) {
				System.err.print( StringUtils.rightPad(row,rowNameColWidth," " ).substring(0,rowNameColWidth));
				System.err.print( " " );
				for ( String col : table.columnKeySet() ) {
					if ( !col.contentEquals( "|||" ) ) {
						int colWidth = getMaxWidth( col );
						Set<String> values = table.get(row,col);
						String value =  "";
						if ( values != null ) {
							value = String.join(",", values );
						}
						System.err.print( StringUtils.rightPad(value,colWidth," " ).substring(0,colWidth));
						System.err.print( " " );
					}
				}
				System.err.println();
			}
		}
		System.err.println();
	}

	private int getMaxWidth( String col ) {
		int width = 4;
		if ( col.length() > width ) {
			width = col.length();
		}
		for ( String row : table.rowKeySet() ) {
			Set<String> values = table.get(row, col);
			if ( values != null ) {
				String val = String.join(",", values );
				if ( val != null && val.length() > width ) {
					width = val.length();
				}
			}
		}
		return width;
	}
	
	public String toString() {
		return name + " (" + rows + "," + cols + "," +data + ")";
	}
}
