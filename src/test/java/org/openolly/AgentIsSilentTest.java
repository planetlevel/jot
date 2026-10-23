package org.openolly;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.EventBus;

/** The agent runs inside someone else's application, so it says nothing to the console or the JVM's logging unless asked. */
class AgentIsSilentTest {

	private PrintStream out, err;
	private ByteArrayOutputStream outBytes, errBytes;
	private final List<LogRecord> records = new ArrayList<LogRecord>();
	private Handler handler;

	@BeforeEach
	void listen() {
		out = System.out;
		err = System.err;
		outBytes = new ByteArrayOutputStream();
		errBytes = new ByteArrayOutputStream();
		System.setOut( new PrintStream( outBytes ) );
		System.setErr( new PrintStream( errBytes ) );
		handler = new Handler() {
			public void publish(LogRecord record) { records.add( record ); }
			public void flush() { }
			public void close() { }
		};
		Logger.getLogger( "" ).addHandler( handler );
	}

	@AfterEach
	void restore() {
		System.setOut( out );
		System.setErr( err );
		Logger.getLogger( "" ).removeHandler( handler );
		EventBus.shutdown();
	}

	@Test
	void mistakesInAJotsFileAndFailingCapturesAndBadOutputSettingsSayNothing(@TempDir Path dir) throws Exception {
		Path jot = dir.resolve( "broken.jot" );
		Files.writeString( jot, String.join( "\n",
			"sensors:",
			"- name: quiet-bad",
			"  methods:",
			"  - static not a method",
			"- name: quiet-fine",
			"  methods:",
			"  - java.lang.String.length",
			"  captures:",
			"    value: '#P0.noSuchMethod()'",
			"" ) );
		System.setProperty( "jot.output", "nonsense" );
		try {
			EventBus.configureFromSystemProperties();
		} finally {
			System.clearProperty( "jot.output" );
		}
		ConfigReader.load( jot.toFile() );
		Sensor.getSensors().stream().filter( s -> "quiet-fine".equals( s.getName() ) ).forEach(
			s -> s.execute( "t", "sig", null, new Object[] { "x" }, null ) );
		EventBus.shutdown();
		Assertions.assertEquals( "", outBytes.toString(), "nothing on standard out" );
		Assertions.assertEquals( "", errBytes.toString(), "nothing on standard error" );
		Assertions.assertTrue( records.isEmpty(), "nothing to the JVM's logging, " + records );
	}

	@Test
	void withTheOutputSetToNothingNothingIsWritten() throws Exception {
		System.setProperty( "jot.output", "" );
		try {
			EventBus.configureFromSystemProperties();
		} finally {
			System.clearProperty( "jot.output" );
		}
		EventBus.publish( new org.openolly.reporting.Event( "quiet", "x", Thread.currentThread().getStackTrace() ) );
		EventBus.shutdown();
		Assertions.assertEquals( "", errBytes.toString() );
		Assertions.assertEquals( "", outBytes.toString() );
	}

	@Test
	void withNoOutputSettingEventsGoToAFileInTheDotJotFolderAndNotToTheApplication(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
		System.clearProperty( "jot.output" );
		System.clearProperty( "jot.output.file" );
		System.setProperty( "jot.dir", dir.resolve( ".jot" ).toString() );
		try {
			EventBus.configureFromSystemProperties();
			EventBus.publish( new org.openolly.reporting.Event( "quiet", "x", Thread.currentThread().getStackTrace() ) );
			EventBus.shutdown();
		} finally {
			System.clearProperty( "jot.dir" );
		}
		Assertions.assertTrue( Files.size( dir.resolve( ".jot/events.jsonl" ) ) > 0, "the event is in the file" );
		Assertions.assertEquals( "", errBytes.toString() );
		Assertions.assertEquals( "", outBytes.toString() );
	}
}
