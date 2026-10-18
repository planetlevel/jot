package org.openolly;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openolly.advice.SensorException;
import org.openolly.config.ControlFile;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

class ControlFileTest {

	@TempDir
	Path dir;
	Path file;
	List<Event> events;
	Sensor a;
	Sensor b;

	@BeforeEach
	void setUp() {
		file = dir.resolve( "control.yaml" );
		events = new ArrayList<Event>();
		EventBus.configure( List.of( (EventSink) events::add ), 100 );
		a = new Sensor().name( "rule-a" ).method( "x.Y.a" ).capture( "#P0" ).exception( "no a" );
		b = new Sensor().name( "rule-b" ).method( "x.Y.b" ).capture( "#P0" ).exception( "no b" ).protect( false );
	}

	@AfterEach
	void tearDown() {
		Sensor.applyControl( true, java.util.Map.of() );
		Sensor.protectAll( true );
		EventBus.shutdown();
	}

	private boolean apply(String json) throws IOException {
		Files.writeString( file, json );
		return new ControlFile( file ).poll();
	}

	private List<String> changes() {
		EventBus.shutdown();
		List<String> out = new ArrayList<String>();
		for ( Event e : events ) if ( e.getRule().equals( "jot-control" ) ) out.add( e.getCapture() );
		return out;
	}

	@Test
	void testWithoutAFileNothingChanges() {
		Assertions.assertFalse( new ControlFile( file ).poll() );
		Assertions.assertTrue( a.isProtected() );
		Assertions.assertFalse( b.isProtected() );
	}

	@Test
	void testMasterSwitchOffMakesEveryRuleReportOnly() throws IOException {
		Assertions.assertTrue( apply( "{\"v\":1,\"protect\":false}" ) );
		Assertions.assertFalse( a.isProtected() );
		Assertions.assertFalse( b.isProtected() );
		Assertions.assertEquals( List.of( "protect=off" ), changes() );
	}

	@Test
	void testOneRuleCanBeSwitchedToMonitorAndOthersKeepBlocking() throws IOException {
		apply( "{\"v\":1,\"protect\":true,\"rules\":{\"rule-a\":false}}" );
		Assertions.assertFalse( a.isProtected() );
		Assertions.assertFalse( b.isProtected() );   // still its own protect: false
		Assertions.assertEquals( List.of( "rule-a=monitor" ), changes() );
	}

	@Test
	void testTheFileCanSwitchOnARuleThatTheJotFileStagedAsReportOnly() throws IOException {
		apply( "{\"rules\":{\"rule-b\":true}}" );
		Assertions.assertTrue( b.isProtected() );
		Assertions.assertThrows( SensorException.class, () -> b.execute( "t", "sig", null, new Object[] { "x" }, null ) );
	}

	@Test
	void testARuleLeftOutGoesBackToItsJotSetting() throws IOException {
		apply( "{\"rules\":{\"rule-a\":false,\"rule-b\":true}}" );
		ControlFile control = new ControlFile( file );
		control.poll();
		Files.writeString( file, "{\"rules\":{}}" );
		Assertions.assertTrue( control.poll() );
		Assertions.assertTrue( a.isProtected() );
		Assertions.assertFalse( b.isProtected() );
		Assertions.assertTrue( changes().contains( "rule-a=default" ) );
	}

	private void call(Sensor s) {
		s.execute( "t", "sig", null, new Object[] { "x" }, null );
	}

	@Test
	void testADisabledRuleNeitherBlocksNorReports() throws IOException {
		apply( "{\"sensors\":{\"rule-a\":{\"enabled\":false}}}" );
		Assertions.assertFalse( a.isEnabled() );
		Assertions.assertTrue( b.isEnabled() );
		Assertions.assertDoesNotThrow( () -> call( a ) );
		EventBus.shutdown();
		for ( Event e : events ) Assertions.assertNotEquals( "rule-a", e.getRule(), "a disabled rule publishes nothing" );
		Assertions.assertTrue( changes().contains( "rule-a=disabled" ) );
	}

	@Test
	void testARuleTakenOffTheDisabledSettingBlocksAgainAndGoesBackToDefault() throws IOException {
		ControlFile control = new ControlFile( file );
		Files.writeString( file, "{\"sensors\":{\"rule-a\":{\"enabled\":false}}}" );
		control.poll();
		Files.writeString( file, "{\"sensors\":{}}" );
		Assertions.assertTrue( control.poll() );
		Assertions.assertTrue( a.isEnabled() );
		Assertions.assertThrows( SensorException.class, () -> call( a ) );
		Assertions.assertTrue( changes().contains( "rule-a=default" ) );
	}

	@Test
	void testASensorThatOnlyObservesCanBeDisabledToo() throws IOException {
		Sensor plain = new Sensor().name( "plain" ).method( "x.Y.c" ).capture( "#P0" );
		Assertions.assertTrue( plain.isEnabled() );
		apply( "{\"sensors\":{\"plain\":{\"enabled\":false}}}" );
		Assertions.assertFalse( plain.isEnabled() );
		Assertions.assertTrue( plain.execute( "t", "sig", null, new Object[] { "x" }, null ).isEmpty(), "a disabled sensor records nothing" );
		EventBus.shutdown();
		for ( Event e : events ) Assertions.assertNotEquals( "plain", e.getRule() );
	}

	@Test
	void testASensorWrittenWithEnabledFalseIsOffAndTheControlFileCanSwitchItOn() throws IOException {
		Sensor off = new Sensor().name( "off" ).method( "x.Y.d" ).capture( "#P0" ).enabled( false );
		Assertions.assertFalse( off.isEnabled() );
		Assertions.assertTrue( off.execute( "t", "sig", null, new Object[] { "x" }, null ).isEmpty() );
		apply( "{\"sensors\":{\"off\":{\"enabled\":true}}}" );
		Assertions.assertTrue( off.isEnabled() );
		Assertions.assertFalse( off.execute( "t", "sig", null, new Object[] { "x" }, null ).isEmpty() );
	}

	@Test
	void testTurningARuleOffLeavesItsProtectSettingAlone() throws IOException {
		apply( "{\"sensors\":{\"rule-b\":{\"protect\":true,\"enabled\":false}}}" );
		Assertions.assertTrue( b.isProtected() );
		Assertions.assertFalse( b.isEnabled() );
		Assertions.assertDoesNotThrow( () -> call( b ) );
	}

	@Test
	void testProtectCanBeWrittenUnderTheSensorAndWinsOverTheOlderRulesMap() throws IOException {
		apply( "{\"rules\":{\"rule-a\":false},\"sensors\":{\"rule-a\":{\"protect\":true}}}" );
		Assertions.assertTrue( a.isProtected() );
		apply( "{\"sensors\":{\"rule-a\":{\"protect\":false}}}" );
		Assertions.assertFalse( a.isProtected() );
	}

	@Test
	void testTheFileCannotOverrideTheStartupSwitch() throws IOException {
		Sensor.protectAll( false );
		apply( "{\"protect\":true,\"rules\":{\"rule-a\":true}}" );
		Assertions.assertFalse( a.isProtected() );
	}

	@Test
	void testBadContentKeepsTheLastSettings() throws IOException {
		ControlFile control = new ControlFile( file );
		Files.writeString( file, "{\"rules\":{\"rule-a\":false}}" );
		Assertions.assertTrue( control.poll() );
		for ( String bad : List.of( "not json", "[]", "{\"protect\":\"no\"}", "{\"rules\":[]}", "{\"rules\":{\"rule-a\":\"yes\"}}", "{\"sensors\":[]}", "{\"sensors\":{\"rule-a\":true}}", "{\"sensors\":{\"rule-a\":{\"enabled\":\"no\"}}}", "{\"sensors\":{\"rule-a\":{\"enable\":false}}}",
				"{\"v\":2}", "" ) ) {
			Files.writeString( file, bad );
			Assertions.assertFalse( control.poll(), bad );
			Assertions.assertFalse( a.isProtected(), "last good settings stay in force after: " + bad );
		}
	}

	@Test
	void testDeletingTheFileKeepsTheLastSettings() throws IOException {
		ControlFile control = new ControlFile( file );
		Files.writeString( file, "{\"protect\":false}" );
		control.poll();
		Files.delete( file );
		Assertions.assertFalse( control.poll() );
		Assertions.assertFalse( a.isProtected() );
	}

	@Test
	void testAnOversizedFileIsIgnored() throws IOException {
		Files.writeString( file, "{\"protect\":false,\"pad\":\"" + "x".repeat( 70 * 1024 ) + "\"}" );
		Assertions.assertFalse( new ControlFile( file ).poll() );
		Assertions.assertTrue( a.isProtected() );
	}

	@Test
	void testReadingTheSameContentTwiceChangesAndReportsNothingTheSecondTime() throws IOException {
		ControlFile control = new ControlFile( file );
		Files.writeString( file, "{\"rules\":{\"rule-a\":false}}" );
		Assertions.assertTrue( control.poll() );
		Assertions.assertFalse( control.poll() );
		Assertions.assertEquals( List.of( "rule-a=monitor" ), changes() );
	}

	@Test
	void testNamesThatMatchNoSensorAreIgnored() throws IOException {
		Assertions.assertTrue( apply( "{\"rules\":{\"nobody\":false}}" ) );
		Assertions.assertTrue( a.isProtected() );
	}

	@Test
	void testASwitchedRuleReportsInsteadOfBlockingAtOnce() throws IOException {
		List<Object> before = null;
		Assertions.assertThrows( SensorException.class, () -> a.execute( "t", "sig", null, new Object[] { "x" }, null ) );
		apply( "{\"rules\":{\"rule-a\":false}}" );
		Assertions.assertEquals( 1, a.execute( "t", "sig", null, new Object[] { "x" }, null ).size() );
		EventBus.shutdown();
		List<Event.Action> actions = new ArrayList<Event.Action>();
		for ( Event e : events ) if ( e.getRule().startsWith( "rule-a-" ) ) actions.add( e.getAction() );
		Assertions.assertEquals( List.of( Event.Action.BLOCKED, Event.Action.MONITORED ), actions );
	}

}
