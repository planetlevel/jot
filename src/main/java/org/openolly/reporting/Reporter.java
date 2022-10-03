package org.openolly.reporting;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.google.common.flogger.FluentLogger;

public class Reporter {
	private static final FluentLogger logger = FluentLogger.forEnclosingClass();
	
	private static List<Report> reports = new ArrayList<Report>();

	public Reporter() {
//		new Timer().scheduleAtFixedRate( this, 10*1000, 5*1000);
//		System.out.println( "Reporting thread started" );
	}
	
	public static void update(Trace t) {
		for ( Report table : reports ) {
			try {
				table.update( t );
				table.dump();
			} catch( Exception e ) {
				//e.printStackTrace();
				logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
			}
		}
	}

	public static void add(Report table) {
		reports.add( table );
	}

	public static List<Report> getReports() {
		return reports;
	}

	
}