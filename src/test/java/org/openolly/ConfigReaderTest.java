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
		File jots = new File("src/test/resources/jot.yaml");
		ConfigReader.init( jots.getAbsolutePath() );
	}

	@Test
	void aReportsSectionIsForTheDashboardAndTheAgentLeavesItAlone(@TempDir Path dir) throws Exception {
		Path jot = dir.resolve( "reports.jot" );
		Files.writeString( jot, String.join( "\n",
			"sensors:",
			"- name: rep-sensor",
			"  methods:",
			"  - java.lang.String.length",
			"  captures:",
			"    value: '#P0'",
			"reports:",
			"- name: 'Ciphers'",
			"  type: 'list'",
			"  cols: 'rep-sensor.value'",
			"" ) );
		ConfigReader.load( jot.toFile() );
		Assertions.assertTrue( ConfigReader.getProblems().stream().noneMatch( p -> p.contains( "report" ) ), "a reports section is not a problem" );
		Assertions.assertTrue( Sensor.exists( "rep-sensor" ), "and the sensors beside it load" );
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
		org.openolly.config.StartupReport.publish( "jot.yaml" );
		EventBus.shutdown();
		Assertions.assertTrue( said.stream().anyMatch( x -> x.startsWith( "problem=report.jot sr-bad exception is no longer a setting" ) ), said.toString() );
	}

	@Test
	void everyJotFileInTheRepositoryLoadsWithNoProblems() throws Exception {
		int before = ConfigReader.getProblems().size();
		int files = 0;
		for ( String where : java.util.List.of( "cves", "catalog" ) ) {
			for ( File f : ConfigReader.jotFiles( new File( where ) ) ) {
				ConfigReader.load( f );
				files++;
			}
		}
		// the demo's configuration is one file, which is a jots file with its sensors, rules and reports in it
		ConfigReader.load( new File( "demo/ticketbook/.jot/jot.yaml" ), true );
		files++;
		Assertions.assertTrue( files > 10, "found only " + files + " files" );
		Assertions.assertEquals( java.util.List.of(), ConfigReader.getProblems().subList( before, ConfigReader.getProblems().size() ) );
	}

	private static java.util.List<String> newProblems(int before) {
		return new java.util.ArrayList<String>( ConfigReader.getProblems().subList( before, ConfigReader.getProblems().size() ) );
	}

	@Test
	void aJotsFileCanHoldItsOwnSensorsAndReportsAndTheRestOfTheConfigurationBesideThem(@TempDir Path dir) throws Exception {
		Path file = dir.resolve( "jot.yaml" );
		Files.writeString( file, String.join( "\n",
			"app:", "  entry:", "  - com.acme.Main.main", "  packages:", "  - com.acme",
			"ignore:", "- java.lang.ClassLoader",
			"sensors:", "- name: 'one-file-sensor'", "  methods:", "  - 'java.lang.String.length'", "  captures:", "    value: '#P0'",
			"- name: 'one-file-rule'", "  description: 'Identifies a call'", "  methods:", "  - 'java.lang.String.isBlank'", "  block-when: true", "  protect: false",
			"reports:", "- name: 'One file report'", "  type: 'list'", "  cols: 'one-file-sensor.value'", "" ) );
		int before = ConfigReader.getProblems().size();
		ConfigReader.init( file.toString() );
		Assertions.assertTrue( Sensor.exists( "one-file-sensor" ), "a sensor of the jots file itself is loaded" );
		Assertions.assertTrue( Sensor.exists( "one-file-rule" ), "and so is a rule" );
		Assertions.assertEquals( java.util.List.of(), newProblems( before ), "none of it is a mistake, sensors, reports, app and ignore are all settings of this file" );
		Assertions.assertEquals( 1, AppScope.entries().size(), "the entry points of the same file are used" );
		Assertions.assertTrue( Sensor.getSensors().stream().anyMatch( x -> "one-file-rule".equals( x.getName() ) && x.getBlockWhen() != null ) );
	}

	@Test
	void whatTheJotsFileDefinesIsUsedOverWhatAFileItListsDefinesAndTheRestOfThatFileStillLoads(@TempDir Path dir) throws Exception {
		Files.writeString( dir.resolve( "lib.jot" ), String.join( "\n",
			"sensors:", "- name: 'one-file-dup'", "  description: 'Identifies the one in the library'", "  methods:", "  - 'java.lang.String.length'", "  captures:", "    value: '#P0'",
			"- name: 'one-file-library-only'", "  methods:", "  - 'java.lang.String.isEmpty'", "  captures:", "    value: '#P0'", "" ) );
		Path file = dir.resolve( "jot.yaml" );
		Files.writeString( file, String.join( "\n",
			"jots:", "- lib.jot",
			"sensors:", "- name: 'one-file-dup'", "  description: 'Identifies the one in the jots file'", "  methods:", "  - 'java.lang.String.length'", "  captures:", "    value: '#P0'", "" ) );
		ConfigReader.init( file.toString() );
		Assertions.assertEquals( "Identifies the one in the jots file", Sensor.getSensors().stream().filter( x -> "one-file-dup".equals( x.getName() ) ).findFirst().get().getDescription(),
			"the first definition wins, and the jots file is read first, so a library can be listed and still be overridden" );
		Assertions.assertTrue( Sensor.exists( "one-file-library-only" ), "and the library's other sensor is loaded" );
	}

	@Test
	void aJotFileThatIsNotTheJotsFileStillMayNotHaveTheSettingsOfOne(@TempDir Path dir) throws Exception {
		Path jot = dir.resolve( "not-main.jot" );
		Files.writeString( jot, "app:\n  entry: []\nignore: []\nsensors:\n- name: 'one-file-not-main'\n  methods:\n  - 'java.lang.String.length'\n  captures:\n    value: '#P0'\n" );
		int before = ConfigReader.getProblems().size();
		ConfigReader.load( jot.toFile() );
		java.util.List<String> said = newProblems( before );
		Assertions.assertTrue( said.stream().anyMatch( t -> t.contains( "app is not a section" ) ), said.toString() );
		Assertions.assertTrue( said.stream().anyMatch( t -> t.contains( "ignore is not a section" ) ), said.toString() );
		Assertions.assertTrue( Sensor.exists( "one-file-not-main" ), "and the sensor in it is still loaded" );
	}

	@Test
	void aSettingThatIsNotOneIsSaidEvenInTheJotsFile(@TempDir Path dir) throws Exception {
		Path file = dir.resolve( "jot.yaml" );
		Files.writeString( file, "colour: red\nsensors:\n- name: 'one-file-colour'\n  methods:\n  - 'java.lang.String.length'\n  captures:\n    value: '#P0'\n" );
		int before = ConfigReader.getProblems().size();
		ConfigReader.init( file.toString() );
		java.util.List<String> said = newProblems( before );
		Assertions.assertTrue( said.stream().anyMatch( t -> t.contains( "colour is not a setting of a jots file" ) && t.contains( "sensors and reports" ) ), said.toString() );
		Assertions.assertTrue( Sensor.exists( "one-file-colour" ), "and what is right in the file is loaded" );
	}

	@Test
	void theTicketbookConfigurationIsOneFileAndTheAgentLoadsAllOfItWithNoProblems() throws Exception {
		int before = ConfigReader.getProblems().size();
		int sensors = Sensor.getSensors().size();
		ConfigReader.init( "demo/ticketbook/.jot/jot.yaml" );
		System.clearProperty( "jot.control" );
		Assertions.assertEquals( java.util.List.of(), newProblems( before ), "nothing in it is a mistake" );
		Assertions.assertEquals( 2, AppScope.entries().size(), "its own entry points are the application's scope" );
		// what the file defines itself, and not only what it lists, which is the point of one file
		for ( String name : java.util.List.of( "http-route", "auth-user", "crypto-cipher", "http-parameter-sensitive-name", "http-cookie-sensitive-value", "native-process", "jvm-exit" ) ) {
			Assertions.assertTrue( Sensor.exists( name ), name + " is defined in jot.yaml and was not loaded" );
		}
		Assertions.assertTrue( Sensor.exists( "cve-2022-22965" ), "and so is a library it lists" );
		Assertions.assertTrue( Sensor.getSensors().size() >= sensors, "nothing was lost" );
	}

	@Test
	void jotsFileListsEverythingAndSearchesDirectoriesRecursively(@TempDir Path dir) throws Exception {
		Path rules = Files.createDirectories( dir.resolve( "rules/deep" ) );
		Files.writeString( dir.resolve( "base.jot" ), "sensors:\n- name: 'jots-base'\n  methods:\n  - 'java.lang.String.length'\n" );
		Files.writeString( rules.resolve( "r.jot" ), "sensors:\n- name: 'jots-rule'\n  methods:\n  - 'java.lang.String.isEmpty'\n" );
		Files.writeString( rules.resolve( "notes.txt" ), "not a jot" );
		Path jotsFile = dir.resolve( "jot.yaml" );
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


	@Test
	public void theJotsFileIsFoundInTheDotJotDirectoryFirstThenTheFolderItself() throws Exception {
		java.nio.file.Path dir = java.nio.file.Files.createTempDirectory( "locate" );
		File plain = new File( dir.toFile(), "jot.yaml" );
		java.nio.file.Files.writeString( plain.toPath(), "sensors: []\n" );
		Assertions.assertEquals( plain.getPath(), ConfigReader.locate( dir.toString() ), "jot.yaml in the folder" );
		File hidden = new File( dir.toFile(), ".jot/jot.yaml" );
		hidden.getParentFile().mkdirs();
		java.nio.file.Files.writeString( hidden.toPath(), "sensors: []\n" );
		Assertions.assertEquals( hidden.getPath(), ConfigReader.locate( dir.toString() ), ".jot/jot.yaml wins over jot.yaml" );
		Assertions.assertEquals( hidden.getPath(), ConfigReader.locate( hidden.getParent() ), "the .jot directory itself" );
		Assertions.assertEquals( plain.getPath(), ConfigReader.locate( plain.getPath() ), "a file is used as it is" );
	}
}
