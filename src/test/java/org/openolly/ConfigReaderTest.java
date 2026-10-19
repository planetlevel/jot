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

	@org.junit.jupiter.api.AfterEach
	void noApplicationScopeLeftBehind() {
		AppScope.configure( java.util.List.of() );      // reading a jots file sets it, and other tests run sensors with no entry point
		PlatformWork.configure( null );
	}

	@Test
	void readerTest() throws IOException {
		File jots = new File("src/test/resources/jots.yaml");
		ConfigReader.init( jots.getAbsolutePath() );
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

	@Test
	void aSensorWrittenWithEnabledFalseIsOffAndTheOthersAreOn(@TempDir Path dir) throws Exception {
		Path jot = dir.resolve( "enabled.jot" );
		Files.writeString( jot, String.join( "\n",
			"sensors:",
			"- name: 'enabled-off'",
			"  enabled: false",
			"  methods:",
			"  - 'java.lang.String.length'",
			"- name: 'enabled-on'",
			"  enabled: true",
			"  methods:",
			"  - 'java.lang.String.isEmpty'",
			"- name: 'enabled-unsaid'",
			"  methods:",
			"  - 'java.lang.String.trim'",
			"" ) );
		ConfigReader.load( jot.toFile() );
		var byName = new java.util.HashMap<String, Sensor>();
		for ( Sensor sensor : Sensor.getSensors() ) byName.put( sensor.getName(), sensor );
		Assertions.assertFalse( byName.get( "enabled-off" ).isEnabled() );
		Assertions.assertTrue( byName.get( "enabled-on" ).isEnabled() );
		Assertions.assertTrue( byName.get( "enabled-unsaid" ).isEnabled(), "a sensor is on unless it says otherwise" );
	}

	@Test
	void blockWhenMakesARuleFromTheFileWhetherItIsTrueOrAnExpression(@TempDir Path dir) throws Exception {
		Path jot = dir.resolve( "blockwhen.jot" );
		Files.writeString( jot, String.join( "\n",
			"sensors:",
			"- name: bw-always",
			"  description: A web request started a process",
			"  methods:",
			"  - java.lang.String.length",
			"  block-when: true",
			"- name: bw-condition",
			"  description: A key was too small",
			"  methods:",
			"  - java.lang.String.isEmpty",
			"  captures:",
			"    size: '#P0'",
			"  block-when: '#P0 < 2048'",
			"- name: bw-sensor",
			"  methods:",
			"  - java.lang.String.strip",
			"" ) );
		ConfigReader.load( jot.toFile() );
		var byName = new java.util.HashMap<String, Sensor>();
		for ( Sensor sensor : Sensor.getSensors() ) byName.put( sensor.getName(), sensor );
		Assertions.assertEquals( "A web request started a process", byName.get( "bw-always" ).getRuleMessage() );
		Assertions.assertEquals( "A key was too small: #P0 < 2048", byName.get( "bw-condition" ).getRuleMessage() );
		Assertions.assertEquals( "#P0 < 2048", byName.get( "bw-condition" ).getBlockWhen() );
		Assertions.assertFalse( byName.get( "bw-sensor" ).isRule(), "no block-when, so it only records" );
	}

	/** Loads a file and says what was left out, as the lines the reader recorded, and which sensors came to be. */
	private java.util.List<String> loadAndReport(Path dir, String file, String text, java.util.List<String> names) throws Exception {
		Path jot = dir.resolve( file );
		Files.writeString( jot, text );
		int before = ConfigReader.getProblems().size();
		ConfigReader.load( jot.toFile() );
		java.util.List<String> said = new ArrayList<String>( ConfigReader.getProblems().subList( before, ConfigReader.getProblems().size() ) );
		for ( String name : names ) said.add( ( Sensor.exists( name ) ? "loaded " : "left out " ) + name );
		return said;
	}

	private String allOf(java.util.List<String> said) {
		return String.join( "\n", said );
	}

	@Test
	void aSensorOrRuleThatSaysSomethingWrongIsLeftOutAndSaidSoAndTheRestOfTheFileLoads(@TempDir Path dir) throws Exception {
		String text = String.join( "\n",
			"sensors:",
			"- name: vd-fine",
			"  methods:",
			"  - java.lang.String.length",
			"- name: vd-old",
			"  methods:",
			"  - java.lang.String.isEmpty",
			"  exception: Not allowed",
			"- name: vd-typo",
			"  methods:",
			"  - java.lang.String.trim",
			"  block_when: true",
			"- name: vd-empty",
			"  methods:",
			"  - java.lang.String.strip",
			"  block-when:",
			"- name: vd-five",
			"  methods:",
			"  - java.lang.String.toLowerCase",
			"  block-when: 5",
			"- name: vd-never",
			"  methods:",
			"  - java.lang.String.toUpperCase",
			"  block-when: false",
			"- name: vd-comment",
			"  methods:",
			"  - java.lang.String.concat",
			"  captures:",
			"    path:",
			"- name: vd-list",
			"  methods:",
			"  - java.lang.String.codePointCount",
			"  captures:",
			"  - '#P0'",
			"- name: vd-field",
			"  methods:",
			"  - java.lang.String.codePointBefore",
			"  captures:",
			"    Path: '#P0'",
			"- name: vd-nofield",
			"  methods:",
			"  - java.lang.String.offsetByCodePoints",
			"  captures:",
			"    path: '#P0'",
			"  matchers:",
			"    name:",
			"    - x",
			"- name: vd-protect",
			"  methods:",
			"  - java.lang.String.charAt",
			"  protect: false",
			"- name: vd-nomethods",
			"  block-when: true",
			"- name: vd-badexpr",
			"  methods:",
			"  - java.lang.String.codePointAt",
			"  block-when: '#P0 ==== ('",
			"- name: vd-badmatcher",
			"  methods:",
			"  - java.lang.String.indexOf",
			"  captures:",
			"    value: '#P0'",
			"  matchers:",
			"    value:",
			"    - '(open'",
			"- name: vd-enabled",
			"  methods:",
			"  - java.lang.String.lastIndexOf",
			"  enabled: maybe",
			"- name: vd-static",
			"  methods:",
			"  - static java.nio.file.Files.write",
			"- name: vd-params",
			"  methods:",
			"  - java.io.File.<init>(java.lang.String)",
			"- name: vd-scope-annotation",
			"  methods:",
			"  - java.io.File.<init>",
			"  scopes:",
			"  - '@a.b.Annotation'",
			"- name: vd-annotation-ok",
			"  methods:",
			"  - '@a.b.Annotation'",
			"  captures:",
			"    caller: '#CALLER'",
			"- name: Vd_Name",
			"  methods:",
			"  - java.lang.String.intern",
			"" );
		java.util.List<String> said = loadAndReport( dir, "wrong.jot", text, java.util.List.of( "vd-fine", "vd-old", "vd-typo", "vd-empty",
			"vd-five", "vd-never", "vd-comment", "vd-list", "vd-field", "vd-nofield", "vd-protect", "vd-nomethods", "vd-badexpr", "vd-badmatcher", "vd-enabled", "Vd_Name", "vd-static", "vd-params", "vd-scope-annotation", "vd-annotation-ok" ) );
		String all = allOf( said );
		Assertions.assertTrue( all.contains( "loaded vd-annotation-ok" ), "an annotation is a fine way to name methods" );
		Assertions.assertTrue( all.contains( "vd-static methods item 1, static java.nio.file.Files.write, isn't a method name, write package.Class.method with no static" ), all );
		Assertions.assertTrue( all.contains( "vd-params methods item 1" ), all );
		Assertions.assertTrue( all.contains( "vd-scope-annotation scopes item 1, @a.b.Annotation, isn't a method name" ), "a scope can't be an annotation\n" + all );
		Assertions.assertTrue( all.contains( "loaded vd-fine" ), "what is right in the same file still loads" );
		for ( String bad : java.util.List.of( "vd-old", "vd-typo", "vd-empty", "vd-five", "vd-never", "vd-comment", "vd-list", "vd-field", "vd-nofield", "vd-protect",
				"vd-nomethods", "vd-badexpr", "vd-badmatcher", "vd-enabled", "Vd_Name", "vd-static", "vd-params", "vd-scope-annotation" ) ) {
			Assertions.assertTrue( all.contains( "left out " + bad ), bad + " should have been left out\n" + all );
		}
		Assertions.assertTrue( all.contains( "vd-old exception is no longer a setting, use block-when" ), all );
		Assertions.assertTrue( all.contains( "vd-typo block_when is not a setting" ), all );
		Assertions.assertTrue( all.contains( "vd-empty block-when must be true, or an expression" ), all );
		Assertions.assertTrue( all.contains( "vd-five block-when must be true, or an expression" ), all );
		Assertions.assertTrue( all.contains( "vd-never block-when: false never blocks" ), all );
		Assertions.assertTrue( all.contains( "vd-comment capture path is empty, a # starts a comment" ), all );
		Assertions.assertTrue( all.contains( "vd-list captures must be names and expressions" ), all );
		Assertions.assertTrue( all.contains( "vd-field capture Path should be a lower case name" ), all );
		Assertions.assertTrue( all.contains( "vd-nofield matchers name is not a captured field, the fields are path" ), all );
		Assertions.assertTrue( all.contains( "vd-protect protect only matters for a rule" ), all );
		Assertions.assertTrue( all.contains( "vd-nomethods needs methods" ), all );
		Assertions.assertTrue( all.contains( "vd-badexpr block-when is not an expression" ), all );
		Assertions.assertTrue( all.contains( "vd-badmatcher matchers value item 1 is not a pattern" ), all );
		Assertions.assertTrue( all.contains( "vd-enabled enabled must be true or false" ), all );
		Assertions.assertTrue( all.contains( "Vd_Name the name should be lower case words" ), all );
	}

	@Test
	void aFileWithAWrongSectionOrBrokenYamlIsSaidOutLoudAndNeverThrows(@TempDir Path dir) throws Exception {
		java.util.List<String> typo = loadAndReport( dir, "typo.jot", "sensor:\n- name: vf-typo\n  methods:\n  - java.lang.String.length\n",
			java.util.List.of( "vf-typo" ) );
		Assertions.assertTrue( allOf( typo ).contains( "sensor is not a section, the sections are sensors and reports" ), allOf( typo ) );
		java.util.List<String> broken = loadAndReport( dir, "broken.jot", "sensors:\n- name: vf-broken\n  methods: [a\n", java.util.List.of( "vf-broken" ) );
		Assertions.assertTrue( allOf( broken ).contains( "is not valid YAML, nothing in it was loaded" ), allOf( broken ) );
		java.util.List<String> list = loadAndReport( dir, "list.jot", "- name: vf-list\n", java.util.List.of() );
		Assertions.assertTrue( allOf( list ).contains( "must be a mapping with sensors and reports" ), allOf( list ) );
	}

	@Test
	void theStartupReportListsWhatWasLeftOut(@TempDir Path dir) throws Exception {
		loadAndReport( dir, "report.jot", "sensors:\n- name: sr-bad\n  methods:\n  - java.lang.String.length\n  exception: x\n", java.util.List.of() );
		java.util.List<String> said = new ArrayList<String>();
		EventBus.configure( java.util.List.of( new EventSink() {
			public void accept( Event e ) { if ( "jot-config".equals( e.getRule() ) ) said.add( e.getCapture() ); }
		} ), 10000 );   // the report names every sensor loaded so far, by every test before this one
		org.openolly.config.StartupReport.publish( "jots.yaml" );
		EventBus.shutdown();
		Assertions.assertTrue( said.stream().anyMatch( x -> x.startsWith( "problem=report.jot sr-bad exception is no longer a setting" ) ), said.toString() );
	}

	@Test
	void everyJotFileInTheRepositoryLoadsWithNoProblems() throws Exception {
		int before = ConfigReader.getProblems().size();
		int files = 0;
		for ( String where : java.util.List.of( "cves", "demo/ticketbook/jots", "demo/ticketbook/rules", "src/main/resources" ) ) {
			for ( File f : ConfigReader.jotFiles( new File( where ) ) ) {
				ConfigReader.load( f );
				files++;
			}
		}
		Assertions.assertTrue( files > 15, "found only " + files + " files" );
		Assertions.assertEquals( java.util.List.of(), ConfigReader.getProblems().subList( before, ConfigReader.getProblems().size() ) );
	}

	@Test
	void jotsFileListsEverythingAndSearchesDirectoriesRecursively(@TempDir Path dir) throws Exception {
		Path rules = Files.createDirectories( dir.resolve( "rules/deep" ) );
		Files.writeString( dir.resolve( "base.jot" ), "sensors:\n- name: 'jots-base'\n  methods:\n  - 'java.lang.String.length'\n" );
		Files.writeString( rules.resolve( "r.jot" ), "sensors:\n- name: 'jots-rule'\n  methods:\n  - 'java.lang.String.isEmpty'\n" );
		Files.writeString( rules.resolve( "notes.txt" ), "not a jot" );
		Path jotsFile = dir.resolve( "jots.yaml" );
		Files.writeString( jotsFile, String.join( "\n",
			"jots:",
			"- base.jot",
			"- rules",
			"- missing",
			"control: ctl.json", "" ) );

		var listed = ConfigReader.readJotsFile( jotsFile.toFile() );
		Assertions.assertEquals( 3, listed.size(), listed.toString() );
		Assertions.assertEquals( dir.resolve( "ctl.json" ).toString(), System.getProperty( "jot.control" ) );
		System.clearProperty( "jot.control" );
		Assertions.assertEquals( 1, ConfigReader.jotFiles( dir.resolve( "rules" ).toFile() ).size() );

		ConfigReader.init( jotsFile.toString() );
		Assertions.assertTrue( Sensor.exists( "jots-base" ) );
		Assertions.assertTrue( Sensor.exists( "jots-rule" ) );
		System.clearProperty( "jot.control" );
	}

}
