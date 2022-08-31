package org.openolly.config;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.openolly.Sensor;
import org.openolly.reporting.Report;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.google.common.flogger.FluentLogger;


public class ConfigReader {
	
	private static File yaml = null;
	private static long lastModified = 0;
	
	private static final FluentLogger logger = FluentLogger.forEnclosingClass();
	
	public static boolean isChanged() {
		return lastModified != yaml.lastModified();
	}
	
	public static void init(String filename) throws IOException {
		if ( filename == null ) {
			//System.err.println( "[JOT] Error: no JOT file or directory provided");
			logger.atSevere().log( "[JOT] Error: no JOT file or directory provided");
			//System.err.println( "[JOT] Try using -javaagent:jot-x.x.jar=JOTFILE" );
			logger.atSevere().log( "[JOT] Try using -javaagent:jot-x.x.jar=JOTFILE" );
			return;
		}
		//System.err.println( "[JOT] Loading JOTs from " + filename );
		logger.atWarning().log("[JOT] Loading JOTs from " + filename );
		yaml = new File( filename );
		if ( yaml.isDirectory() ) {
			for ( File f : yaml.listFiles() ) {
				//System.out.println( "Loading JOTs from " + f );
				logger.atInfo().log("Loading JOTs from " + f );
				load( f );
			}
		}
		else {
			load( yaml );
		}
	}	

	
	// FIXME - sensors are added to the Sensor class, Reports are tracked in Reporter
	public static void load( File yaml ) throws IOException {
		ConfigReader.yaml = yaml;
		lastModified = yaml.lastModified();

		// allow fields to be missing
		ObjectMapper mapper = new ObjectMapper(new YAMLFactory())
				.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		
		YAML config = mapper.readValue(yaml, YAML.class);
				
		if ( config.sensors != null ) {
			for ( YAMLSensor entry : config.sensors )  {
				if ( Sensor.exists( entry.name ) ) {
					//System.err.println( "[JOT] WARNING: " + entry.name + " from " + yaml + " already loaded. Skipping." );
					logger.atWarning().log("[JOT] WARNING: " + entry.name + " from " + yaml + " already loaded. Skipping." );
				}

				else if ( entry.name.equals("example")) {					
					//System.err.println( "[JOT] WARNING: Found 'example' JOT in " + yaml + ". Skipping." );
					logger.atWarning().log("[JOT] WARNING: Found 'example' JOT in " + yaml + ". Skipping." );
				}

				else {
					new Sensor()
						.name( entry.name )
						.description( entry.description )
						.methods( entry.methods )
						.scopes( entry.scopes )
						.excludes( entry.excludes )
						.captures( entry.captures )
						.matchers( entry.matchers )
						.exception( entry.exception )
						.debug( entry.debug );
				}
			}
		}
		
		if ( config.reports != null ) {
			for ( YAMLReport entry : config.reports ) {
				if ( !entry.name.contentEquals( "example" )) {
					new Report()
						.name( entry.name )
						.type( entry.type )
						.rows( entry.rows )
						.cols( entry.cols )
						.data( entry.data );
				}
			}
		}
	}
	
	private static class YAML {
		public YAML() {}
		public List<YAMLSensor> sensors = null;
		public List<YAMLReport> reports = null;
	}
	
	private static class YAMLSensor {
		public String name = null;
		public String description = null;
		public List<String> methods = new ArrayList<String>();
		public List<String> scopes = new ArrayList<String>();
		public List<String> excludes = new ArrayList<String>();
		public List<String> captures = new ArrayList<String>();
		public List<String> matchers = new ArrayList<String>();
		public String exception = null;
		public boolean debug = false;
	}

	private static class YAMLReport {
		public String name = null;
		public String type = null;
		public String rows = null;
		public String cols = null;
		public String data = null;
	}
	
	
	public static void write( List<YAML> list) throws Exception, JsonMappingException, IOException {		
		ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
		mapper.writeValue(System.out, list);
	}
	
}
