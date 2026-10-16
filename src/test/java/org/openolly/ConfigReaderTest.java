package org.openolly;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

class ConfigReaderTest {

	@Test
	void readerTest() throws IOException {
		File ruleDir = new File("src/test/resources/rules");;
		ConfigReader.init( ruleDir.getAbsolutePath() );
	}

	@Test
	void reportsBecomeSinksAndBadOnesAreSkipped(@TempDir Path dir) throws Exception {
		Path jot = dir.resolve( "reports.jot" );
		Files.writeString( jot, String.join( "\n",
			"reports:",
			"- name: 'Ciphers'",
			"  type: 'list'",
			"  cols: 'cfg-cipher'",
			"- name: 'Old'",
			"  type: 'series'",
			"  rows: 'a'",
			"  cols: 'b'",
			"- name: 'Incomplete'",
			"  type: 'table'",
			"  cols: 'b'",
			"" ) );

		PrintStream original = System.err;
		ByteArrayOutputStream captured = new ByteArrayOutputStream();
		System.setErr( new PrintStream( captured ) );
		try {
			EventBus.configure( new ArrayList<EventSink>(), 10 );
			ConfigReader.load( jot.toFile() );
			EventBus.publish( new Event( "cfg-cipher", "AES", Thread.currentThread().getStackTrace() ) );
			EventBus.shutdown();
		} finally {
			System.setErr( original );
		}
		String out = captured.toString();
		Assertions.assertTrue( out.contains( "Ciphers" ) && out.contains( "AES" ), out );
	}

}
