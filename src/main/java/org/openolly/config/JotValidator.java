package org.openolly.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.springframework.expression.spel.standard.SpelExpressionParser;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * What a .jot file is allowed to say. A sensor or rule that says something wrong is not loaded, because a mistake that
 * only changes what it does is worse than one that is seen. An empty block-when would turn a rule into a sensor that
 * only observes, and a # that starts a comment would drop a capture, both without a word.
 *
 * The dashboard's editor makes the same checks as it is typed in, in dashboard/store.py check_jot_text.
 */
final class JotValidator {

	static final Set<String> SECTIONS = Set.of( "sensors", "reports" );
	static final Set<String> SENSOR_KEYS = Set.of( "name", "description", "methods", "scopes", "excludes", "captures",
			"matchers", "block-when", "protect", "enabled", "debug" );
	private static final List<String> LISTS = Arrays.asList( "methods", "scopes", "excludes" );
	private static final List<String> BOOLEANS = Arrays.asList( "protect", "enabled", "debug" );
	private static final Pattern FIELD = Pattern.compile( "[a-z][a-z0-9_]*" );
	private static final Pattern NAME = Pattern.compile( "[a-z][a-z0-9]*(\\-[a-z0-9]+)*" );
	private static final Pattern METHOD = Pattern.compile( "([\\p{L}_$][\\p{L}\\p{N}_$]*\\.)+(<init>|[\\p{L}_$][\\p{L}\\p{N}_$]*)" );
	private static final Pattern ANNOTATION = Pattern.compile( "@([\\p{L}_$][\\p{L}\\p{N}_$]*\\.)*[\\p{L}_$][\\p{L}\\p{N}_$]*" );
	private static final SpelExpressionParser SPEL = new SpelExpressionParser();

	private JotValidator() {}

	/** What is wrong with the top of a file, such as sensor: where sensors: was meant. */
	static List<String> fileProblems( JsonNode root ) {
		return fileProblems( root, Set.of() );
	}

	/** also is the sections the file may have besides sensors and reports, which is the settings of a jots file when this is one. */
	static List<String> fileProblems( JsonNode root, Set<String> also ) {
		List<String> problems = new ArrayList<String>();
		if ( root == null || root.isMissingNode() || root.isNull() ) {
			problems.add( "is empty" );
		} else if ( !root.isObject() ) {
			problems.add( "must be a mapping with sensors and reports" );
		} else {
			Iterator<String> keys = root.fieldNames();
			while ( keys.hasNext() ) {
				String key = keys.next();
				if ( !SECTIONS.contains( key ) && !also.contains( key ) ) problems.add( key + " is not a section, the sections are sensors and reports" );
			}
		}
		return problems;
	}

	/** What is wrong with one sensor or rule, empty if nothing is. */
	static List<String> sensorProblems( JsonNode entry ) {
		List<String> problems = new ArrayList<String>();
		if ( !entry.isObject() ) {
			problems.add( "must be a block of name, methods and so on" );
			return problems;
		}
		Iterator<Map.Entry<String, JsonNode>> fields = entry.fields();
		while ( fields.hasNext() ) {
			String key = fields.next().getKey();
			if ( SENSOR_KEYS.contains( key ) ) continue;
			problems.add( key.equals( "exception" ) ? "exception is no longer a setting, use block-when"
					: key + " is not a setting of a sensor" );
		}

		JsonNode name = entry.get( "name" );
		if ( name == null || !name.isTextual() || name.asText().isEmpty() ) {
			problems.add( "needs a name" );
		} else if ( !NAME.matcher( name.asText() ).matches() ) {
			problems.add( "the name should be lower case words joined with -, like crypto-hash" );
		}
		JsonNode description = entry.get( "description" );
		if ( description != null && !description.isTextual() ) problems.add( "description must be text, quote it if it starts with a special character" );

		for ( String list : LISTS ) {
			JsonNode items = entry.get( list );
			if ( items == null ) continue;
			if ( !items.isArray() ) {
				problems.add( list + " must be a list, each item starting with -" );
				continue;
			}
			int n = 0;
			for ( JsonNode item : items ) {
				n++;
				if ( !item.isTextual() || item.asText().trim().isEmpty() ) {
					problems.add( "item " + n + " of " + list + " is " + ( item.isNull() ? "empty, a # starts a comment" : "not text" ) + ", quote it" );
				} else if ( list.equals( "methods" ) || list.equals( "scopes" ) ) {
					String text = item.asText().trim();
					String bare = text.startsWith( "!" ) ? text.substring( 1 ) : text;
					boolean fine = list.equals( "methods" ) && ANNOTATION.matcher( bare ).matches() || METHOD.matcher( bare ).matches();
					if ( !fine ) {
						problems.add( list + " item " + n + ", " + text + ", isn't a method name, write package.Class.method with no static or other"
								+ " modifiers, parameters or return type, and <init> for a constructor" + ( list.equals( "methods" ) ? ", or @package.Annotation" : "" ) );
					}
				}
			}
		}
		fieldProblems( entry, problems );
		if ( !entry.has( "methods" ) || ( entry.get( "methods" ).isArray() && entry.get( "methods" ).size() == 0 ) ) {
			problems.add( "needs methods, the calls it watches" );
		}

		for ( String key : BOOLEANS ) {
			JsonNode value = entry.get( key );
			if ( value == null ) continue;
			boolean fine = value.isBoolean() || ( value.isTextual() && ( value.asText().equals( "true" ) || value.asText().equals( "false" ) ) );
			if ( !fine ) problems.add( key + " must be true or false" );
		}

		JsonNode block = entry.get( "block-when" );
		if ( entry.has( "block-when" ) ) {
			if ( block.isBoolean() ) {
				if ( !block.asBoolean() ) problems.add( "block-when: false never blocks, to switch a rule off write enabled: false" );
			} else if ( !block.isTextual() || block.asText().trim().isEmpty() ) {
				problems.add( "block-when must be true, or an expression for when the call is blocked, like #P0 < 2048" );
			} else if ( !block.asText().trim().equalsIgnoreCase( "true" ) ) {
				expressionProblem( "block-when", block.asText(), problems );
			}
		} else if ( entry.has( "protect" ) ) {
			problems.add( "protect only matters for a rule, which has a block-when" );
		}
		return problems;
	}

	/** captures is field: expression, and matchers is field: [patterns] for fields that are captured. */
	private static void fieldProblems( JsonNode entry, List<String> problems ) {
		JsonNode captures = entry.get( "captures" );
		Set<String> fields = new java.util.LinkedHashSet<String>();
		if ( captures != null ) {
			if ( !captures.isObject() ) {
				problems.add( "captures must be names and expressions, like path: #P0" );
			} else {
				Iterator<Map.Entry<String, JsonNode>> it = captures.fields();
				while ( it.hasNext() ) {
					Map.Entry<String, JsonNode> field = it.next();
					fields.add( field.getKey() );
					if ( !FIELD.matcher( field.getKey() ).matches() ) {
						problems.add( "capture " + field.getKey() + " should be a lower case name like path or remote_ip" );
					}
					if ( !field.getValue().isTextual() || field.getValue().asText().trim().isEmpty() ) {
						problems.add( "capture " + field.getKey() + " is " + ( field.getValue().isNull() ? "empty, a # starts a comment" : "not text" ) + ", quote it" );
					} else {
						expressionProblem( "capture " + field.getKey(), field.getValue().asText(), problems );
					}
				}
			}
		}
		JsonNode matchers = entry.get( "matchers" );
		if ( matchers == null ) return;
		if ( !matchers.isObject() ) {
			problems.add( "matchers must be a captured field and a list of patterns, like path: [ '\\.php$' ]" );
			return;
		}
		Iterator<Map.Entry<String, JsonNode>> it = matchers.fields();
		while ( it.hasNext() ) {
			Map.Entry<String, JsonNode> field = it.next();
			if ( captures != null && captures.isObject() && !fields.contains( field.getKey() ) ) {
				problems.add( "matchers " + field.getKey() + " is not a captured field, the fields are " + String.join( ", ", fields ) );
			}
			if ( !field.getValue().isArray() ) {
				problems.add( "matchers " + field.getKey() + " must be a list, each item starting with -" );
				continue;
			}
			int n = 0;
			for ( JsonNode item : field.getValue() ) {
				n++;
				if ( !item.isTextual() || item.asText().trim().isEmpty() ) {
					problems.add( "item " + n + " of matchers " + field.getKey() + " is " + ( item.isNull() ? "empty, a # starts a comment" : "not text" ) + ", quote it" );
					continue;
				}
				String pattern = item.asText().startsWith( "!" ) ? item.asText().substring( 1 ) : item.asText();
				try {
					Pattern.compile( pattern );
				} catch ( PatternSyntaxException e ) {
					problems.add( "matchers " + field.getKey() + " item " + n + " is not a pattern, " + e.getDescription() );
				}
			}
		}
	}

	private static void expressionProblem( String where, String text, List<String> problems ) {
		try {
			SPEL.parseExpression( text );
		} catch ( RuntimeException e ) {
			problems.add( where + " is not an expression, " + firstLine( e.getMessage() ) );
		}
	}

	private static String firstLine( String message ) {
		if ( message == null ) return "it can't be read";
		int end = message.indexOf( '\n' );
		return end < 0 ? message : message.substring( 0, end );
	}
}
