package org.openolly.config;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.openolly.Sensor;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.Report;
import org.openolly.reporting.RouteGraph;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
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
			logger.atSevere().log( "[JOT] Error: no jots file provided");
			//System.err.println( "[JOT] Try using -javaagent:jot-x.x.jar=jots.yaml" );
			logger.atSevere().log( "[JOT] Try using -javaagent:jot-x.x.jar=jots.yaml" );
			return;
		}
		//System.err.println( "[JOT] Loading JOTs from " + filename );
		logger.atWarning().log("[JOT] Loading JOTs from " + filename );
		// The argument is a jots file, which lists the .jot files and directories to load. The dashboard reads
		// the same file, so the two always agree. The first definition of a name wins.
		File jots = new File( filename.trim() );
		if ( !jots.isFile() || jots.getName().endsWith( ".jot" ) ) {
			logger.atSevere().log( "[JOT] " + jots + " is not a jots file. The agent argument is a jots.yaml that lists "
				+ "the .jot files and directories, like -javaagent:jot.jar=jots.yaml" );
			return;
		}
		List<String> entries = readJotsFile( jots );
		for ( String entry : entries ) {
			if ( entry.isBlank() ) continue;
			File path = new File( entry.trim() );
			if ( !path.exists() ) {
				logger.atWarning().log( "[JOT] " + path + " does not exist. Skipping." );
				continue;
			}
			for ( File f : jotFiles( path ) ) {
				logger.atInfo().log("Loading JOTs from " + f );
				load( f );
			}
		}
	}

	/**
	 * Reads a jots file, shared by the agent and the dashboard.
	 *
	 *   jots:
	 *   - jots                    # a file or directory
	 *   - rules
	 *   control: jot-control.yaml
	 *
	 * Relative paths are relative to the jots file. Returns the absolute paths to load. If -Djot.control isn't
	 * set, the jots file's control path is used.
	 */
	public static List<String> readJotsFile( File jotsFile ) throws IOException {
		ObjectMapper mapper = new ObjectMapper( new YAMLFactory() );
		JsonNode root = mapper.readTree( jotsFile );
		File base = jotsFile.getAbsoluteFile().getParentFile();
		List<String> paths = new ArrayList<>();
		if ( root == null || !root.has( "jots" ) ) {
			logger.atWarning().log( "[JOT] " + jotsFile + " has no jots list" );
		}
		else {
			for ( JsonNode item : root.get( "jots" ) ) {
				String path = item.isTextual() ? item.asText() : item.path( "path" ).asText( null );
				if ( path == null ) continue;
				paths.add( new File( path ).isAbsolute() ? path : new File( base, path ).getPath() );
			}
		}
		if ( root != null && root.hasNonNull( "control" ) && System.getProperty( "jot.control" ) == null ) {
			String control = root.get( "control" ).asText();
			System.setProperty( "jot.control", new File( control ).isAbsolute() ? control : new File( base, control ).getPath() );
		}
		return paths;
	}

	// A file is used as given. A directory contributes every .jot file under it.
	public static List<File> jotFiles( File path ) {
		List<File> found = new ArrayList<>();
		if ( path.isDirectory() ) {
			File[] children = path.listFiles();
			if ( children == null ) return found;
			Arrays.sort( children );
			for ( File child : children ) {
				if ( child.isDirectory() || child.getName().endsWith( ".jot" ) ) {
					found.addAll( jotFiles( child ) );
				}
			}
		}
		else {
			found.add( path );
		}
		return found;
	}

	
	// Sensors are added to the Sensor class, reports are added to the EventBus as sinks
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
						.protect( entry.protect )
						.debug( entry.debug );
				}
			}
		}
		
		if ( config.reports != null ) {
			for ( YAMLReport entry : config.reports ) {
				if ( entry.name == null || entry.name.contentEquals( "example" ) ) continue;
				try {
					addReport( entry );
				} catch ( IllegalArgumentException e ) {
					logger.atWarning().log( "[JOT] Skipping report '" + entry.name + "' in " + yaml + ", " + e.getMessage() );
				}
			}
		}
	}

	private static void addReport( YAMLReport entry ) {
		String type = entry.type == null ? "" : entry.type.trim();
		if ( type.equalsIgnoreCase( "series" ) ) {
			throw new IllegalArgumentException( "series reports were replaced by the event log, see jot.output" );
		}
		if ( type.equalsIgnoreCase( "graph" ) ) {
			if ( entry.rows == null ) throw new IllegalArgumentException( "a graph report needs rows" );
			List<String> forwards = entry.cols == null ? null : Arrays.asList( entry.cols.split( ",\\s*" ) );
			EventBus.addSink( new RouteGraph( entry.name, entry.rows, forwards ) );
			return;
		}
		EventBus.addSink( new Report()
			.name( entry.name )
			.type( type )
			.rows( entry.rows )
			.cols( entry.cols )
			.data( entry.data )
			.validate() );
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
		public Boolean protect = null;
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
