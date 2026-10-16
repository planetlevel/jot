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
		file = dir.resolve( "control.json" );
		events = new ArrayList<Event>();
		EventBus.configure( List.of( (EventSink) events::add ), 100 );
		a = new Sensor().name( "rule-a" ).method( "x.Y.a" ).capture( "#P0" ).exception( "no a" );
		b = new Sensor().name( "rule-b" ).method( "x.Y.b" ).capture( "#P0" ).exception( "no b" ).enforce( false );
	}

	@AfterEach
	void tearDown() {
		Sensor.applyControl( true, java.util.Map.of() );
		Sensor.enforceAll( true );
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
		Assertions.assertTrue( a.isEnforced() );
		Assertions.assertFalse( b.isEnforced() );
	}

	@Test
	void testMasterSwitchOffMakesEveryRuleReportOnly() throws IOException {
		Assertions.assertTrue( apply( "{\"v\":1,\"enforce\":false}" ) );
		Assertions.assertFalse( a.isEnforced() );
		Assertions.assertFalse( b.isEnforced() );
		Assertions.assertEquals( List.of( "enforcement=off" ), changes() );
	}

	@Test
	void testOneRuleCanBeSwitchedToMonitorAndOthersKeepBlocking() throws IOException {
		apply( "{\"v\":1,\"enforce\":true,\"rules\":{\"rule-a\":false}}" );
		Assertions.assertFalse( a.isEnforced() );
		Assertions.assertFalse( b.isEnforced() );   // still its own enforce: false
		Assertions.assertEquals( List.of( "rule-a=monitor" ), changes() );
	}

	@Test
	void testTheFileCanSwitchOnARuleThatTheJotFileStagedAsReportOnly() throws IOException {
		apply( "{\"rules\":{\"rule-b\":true}}" );
		Assertions.assertTrue( b.isEnforced() );
		Assertions.assertThrows( SensorException.class, () -> b.execute( "t", "sig", null, new Object[] { "x" }, null ) );
	}

	@Test
	void testARuleLeftOutGoesBackToItsJotSetting() throws IOException {
		apply( "{\"rules\":{\"rule-a\":false,\"rule-b\":true}}" );
		ControlFile control = new ControlFile( file );
		control.poll();
		Files.writeString( file, "{\"rules\":{}}" );
		Assertions.assertTrue( control.poll() );
		Assertions.assertTrue( a.isEnforced() );
		Assertions.assertFalse( b.isEnforced() );
		Assertions.assertTrue( changes().contains( "rule-a=default" ) );
	}

	@Test
	void testTheFileCannotOverrideTheStartupSwitch() throws IOException {
		Sensor.enforceAll( false );
		apply( "{\"enforce\":true,\"rules\":{\"rule-a\":true}}" );
		Assertions.assertFalse( a.isEnforced() );
	}

	@Test
	void testBadContentKeepsTheLastSettings() throws IOException {
		ControlFile control = new ControlFile( file );
		Files.writeString( file, "{\"rules\":{\"rule-a\":false}}" );
		Assertions.assertTrue( control.poll() );
		for ( String bad : List.of( "not json", "[]", "{\"enforce\":\"no\"}", "{\"rules\":[]}", "{\"rules\":{\"rule-a\":\"yes\"}}",
				"{\"v\":2}", "" ) ) {
			Files.writeString( file, bad );
			Assertions.assertFalse( control.poll(), bad );
			Assertions.assertFalse( a.isEnforced(), "last good settings stay in force after: " + bad );
		}
	}

	@Test
	void testDeletingTheFileKeepsTheLastSettings() throws IOException {
		ControlFile control = new ControlFile( file );
		Files.writeString( file, "{\"enforce\":false}" );
		control.poll();
		Files.delete( file );
		Assertions.assertFalse( control.poll() );
		Assertions.assertFalse( a.isEnforced() );
	}

	@Test
	void testAnOversizedFileIsIgnored() throws IOException {
		Files.writeString( file, "{\"enforce\":false,\"pad\":\"" + "x".repeat( 70 * 1024 ) + "\"}" );
		Assertions.assertFalse( new ControlFile( file ).poll() );
		Assertions.assertTrue( a.isEnforced() );
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
		Assertions.assertTrue( a.isEnforced() );
	}

	@Test
	void testASwitchedRuleReportsInsteadOfBlockingAtOnce() throws IOException {
		List<Object> before = null;
		Assertions.assertThrows( SensorException.class, () -> a.execute( "t", "sig", null, new Object[] { "x" }, null ) );
		apply( "{\"rules\":{\"rule-a\":false}}" );
		Assertions.assertEquals( 1, a.execute( "t", "sig", null, new Object[] { "x" }, null ).size() );
		EventBus.shutdown();
		List<Event.Action> actions = new ArrayList<Event.Action>();
		for ( Event e : events ) if ( e.getRule().equals( "rule-a" ) ) actions.add( e.getAction() );
		Assertions.assertEquals( List.of( Event.Action.BLOCKED, Event.Action.MONITORED ), actions );
	}

}
