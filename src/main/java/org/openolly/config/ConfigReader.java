package org.openolly.config;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.openolly.AppScope;
import org.openolly.PlatformWork;
import org.openolly.Sensor;
import org.openolly.reporting.EventBus;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.openolly.log.FluentLogger;


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
		logger.atInfo().log("Loading JOTs from " + filename );
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
		if ( root != null && root.isObject() ) {
			java.util.Iterator<String> keys = root.fieldNames();
			while ( keys.hasNext() ) {
				String key = keys.next();
				if ( !JOTS_FILE_KEYS.contains( key ) ) problem( jotsFile, null, key + " is not a setting of a jots file, the settings are jots, control, app and ignore" );
			}
		}
		// the application as a scope, and which of its code is its own
		AppScope.configure( null );
		if ( root != null && root.has( "app" ) ) {
			JsonNode app = root.get( "app" );
			if ( !app.isObject() ) {
				problem( jotsFile, null, "app must be a mapping with packages and entry, so the default entry points are used" );
			} else {
				java.util.Iterator<String> names = app.fieldNames();
				while ( names.hasNext() ) {
					String key = names.next();
					if ( !key.equals( "packages" ) && !key.equals( "entry" ) ) problem( jotsFile, null, "app has " + key + ", which is not a setting, the settings are packages and entry" );
				}
				if ( app.has( "entry" ) ) {
					JsonNode entry = app.get( "entry" );
					List<String> entries = new ArrayList<String>();
					boolean fine = entry.isArray();
					if ( fine ) {
						for ( JsonNode item : entry ) {
							String text = item.isTextual() ? item.asText().trim() : "";
							if ( text.isEmpty() || ( !text.startsWith( "@" ) && text.lastIndexOf( '.' ) < 1 ) ) fine = false;
							else entries.add( text );
						}
					}
					if ( fine ) AppScope.configure( entries );
					else problem( jotsFile, null, "app entry must be a list of methods like javax.servlet.Servlet.service or annotations like @org.example.Tool, so the default entry points are used" );
				}
			}
		}
		// the calls that sensors leave out, class loading and page compiling by default
		if ( root != null && root.has( "ignore" ) ) {
			JsonNode ignore = root.get( "ignore" );
			List<String> entries = new ArrayList<String>();
			boolean fine = ignore.isArray();
			if ( fine ) {
				for ( JsonNode item : ignore ) {
					if ( item.isTextual() && !item.asText().trim().isEmpty() ) entries.add( item.asText().trim() );
					else fine = false;
				}
			}
			if ( fine ) PlatformWork.configure( entries );
			else problem( jotsFile, null, "ignore must be a list of packages, classes or methods, so the default list is used" );
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

	
	private static final java.util.Set<String> JOTS_FILE_KEYS = java.util.Set.of( "jots", "control", "app", "ignore" );

	private static final List<String> problems = new ArrayList<String>();

	/** What was wrong in the files that were read, one line for each, which is also why something wasn't loaded. */
	public static List<String> getProblems() {
		return problems;
	}

	private static void problem( File file, String name, String text ) {
		logger.atSevere().log( "[JOT] ERROR: %s in %s %s.%s", name == null ? "the file" : name, file, text, name == null ? "" : " It was not loaded." );
		problems.add( file.getName() + " " + ( name == null ? "" : name + " " ) + text );
	}

	// Sensors are added to the Sensor class. A reports section is for the dashboard, which reads the same files, and the agent leaves it
	// alone. A sensor or rule that says
	// something wrong is left out and said so, see JotValidator, and the rest of the file is still read.
	public static void load( File yaml ) throws IOException {
		ConfigReader.yaml = yaml;
		lastModified = yaml.lastModified();

		// allow fields to be missing
		ObjectMapper mapper = new ObjectMapper(new YAMLFactory())
				.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		JsonNode root;
		try {
			root = mapper.readTree( yaml );
		} catch ( IOException e ) {
			String why = e.getMessage() == null ? "" : e.getMessage().split( "\n" )[0];
			problem( yaml, null, "is not valid YAML, nothing in it was loaded, " + why );
			return;
		}
		for ( String text : JotValidator.fileProblems( root ) ) problem( yaml, null, text );
		if ( root == null || !root.isObject() ) return;

		JsonNode sensors = root.get( "sensors" );
		if ( sensors != null && !sensors.isArray() ) {
			problem( yaml, null, "sensors must be a list, with each sensor starting with - name:" );
		}
		else if ( sensors != null ) {
			for ( JsonNode node : sensors )  {
				String name = node.path( "name" ).isTextual() ? node.path( "name" ).asText() : null;
				if ( "example".equals( name ) ) {
					logger.atWarning().log("[JOT] WARNING: Found 'example' JOT in " + yaml + ". Skipping." );
					continue;
				}
				List<String> bad = JotValidator.sensorProblems( node );
				if ( !bad.isEmpty() ) {
					for ( String text : bad ) problem( yaml, name, text );
					continue;
				}
				if ( Sensor.exists( name ) ) {
					logger.atWarning().log("[JOT] WARNING: " + name + " from " + yaml + " already loaded. Skipping." );
					continue;
				}
				YAMLSensor entry = mapper.treeToValue( node, YAMLSensor.class );
				new Sensor()
					.name( entry.name )
					.description( entry.description )
					.methods( entry.methods )
					.scopes( entry.scopes )
					.excludes( entry.excludes )
					.captures( entry.captures )
					.matchers( entry.matchers )
					.blockWhen( entry.blockWhen )
					.protect( entry.protect )
					.enabled( entry.enabled )
					.debug( entry.debug );
			}
		}
	}
	
	private static class YAML {
		public YAML() {}
		public List<YAMLSensor> sensors = null;
	}
	
	private static class YAMLSensor {
		public String name = null;
		public String description = null;
		public List<String> methods = new ArrayList<String>();
		public List<String> scopes = null;     // none means the application, an empty list means anywhere
		public List<String> excludes = new ArrayList<String>();
		public Map<String, String> captures = new java.util.LinkedHashMap<String, String>();
		public Map<String, List<String>> matchers = new java.util.LinkedHashMap<String, List<String>>();
		@com.fasterxml.jackson.annotation.JsonProperty( "block-when" )
		public String blockWhen = null;
		public Boolean protect = null;
		public Boolean enabled = null;
		public boolean debug = false;
	}

	public static void write( List<YAML> list) throws Exception, JsonMappingException, IOException {		
		ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
		mapper.writeValue(System.out, list);
	}
	
}
