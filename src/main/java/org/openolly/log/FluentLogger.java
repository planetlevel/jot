package org.openolly.log;

import org.openolly.JotScope;

/**
 * The agent's own log, which is silent unless it is asked for. A JOT agent runs inside someone else's application, so it never writes
 * to the application's console or to the JVM's logging. With -Djot.log=/path/jot-agent.log it appends here instead, and
 * -Djot.log.level says how much, severe, warning, info (the default), fine or finest. Nothing is written without the property.
 *
 * It has the calls of the fluent logger it replaced, like logger.atWarning().log( "..." ), so the code that logs reads as it did.
 */
public final class FluentLogger {

	public enum Level { SEVERE, WARNING, INFO, FINE, FINEST }

	private static final String PATH = System.getProperty( "jot.log" );
	private static final Level LEVEL = level( System.getProperty( "jot.log.level" ) );
	private static java.io.PrintWriter out;
	private static boolean failed;

	private final String name;

	private FluentLogger(String name) {
		this.name = name;
	}

	public static FluentLogger forEnclosingClass() {
		String caller = StackWalker.getInstance( StackWalker.Option.RETAIN_CLASS_REFERENCE ).getCallerClass().getSimpleName();
		return new FluentLogger( caller );
	}

	public Api atSevere() { return new Api( this, Level.SEVERE ); }
	public Api atWarning() { return new Api( this, Level.WARNING ); }
	public Api atInfo() { return new Api( this, Level.INFO ); }
	public Api atFine() { return new Api( this, Level.FINE ); }
	public Api atFinest() { return new Api( this, Level.FINEST ); }

	/** True when a message at this level would be written, so a caller can skip building one. */
	public static boolean enabled(Level level) {
		return PATH != null && level.ordinal() <= LEVEL.ordinal();
	}

	private static Level level(String text) {
		if ( text != null ) {
			try {
				return Level.valueOf( text.trim().toUpperCase() );
			} catch ( IllegalArgumentException e ) {
				// the default
			}
		}
		return Level.INFO;
	}

	public static final class Api {
		private final FluentLogger logger;
		private final Level level;
		private Throwable cause;

		Api(FluentLogger logger, Level level) {
			this.logger = logger;
			this.level = level;
		}

		public Api withCause(Throwable cause) {
			this.cause = cause;
			return this;
		}

		public void log(String message) {
			write( message );
		}

		public void log(String format, Object... args) {
			if ( !enabled( level ) ) return;
			String message;
			try {
				message = args == null || args.length == 0 ? format : String.format( format, args );
			} catch ( RuntimeException e ) {
				message = format;
			}
			write( message );
		}

		private void write(String message) {
			if ( !enabled( level ) ) return;
			// writing the file is JOT's own work, which no sensor may see
			JotScope.enter();
			try {
				synchronized ( FluentLogger.class ) {
					if ( failed ) return;
					if ( out == null ) {
						try {
							out = new java.io.PrintWriter( new java.io.FileWriter( PATH, true ) );
						} catch ( java.io.IOException | RuntimeException e ) {
							failed = true;     // a log that can't be written is not worth a word to the application
							return;
						}
					}
					out.println( java.time.Instant.now() + " " + level + " " + logger.name + " " + message );
					if ( cause != null ) cause.printStackTrace( out );
					out.flush();
				}
			} catch ( RuntimeException e ) {
				// never the application's problem
			} finally {
				JotScope.exit();
			}
		}
	}
}
