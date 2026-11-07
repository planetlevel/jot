package org.openolly;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openolly.advice.SensorException;
import org.openolly.reporting.EventBus;
import org.openolly.reporting.EventSink;

/**
 * What a sensor leaves out. A sensor on a class also reaches the classes that extend it, which is how one on java.sql.Statement reaches
 * every driver's statements, and excludes names the types that are not to be instrumented, like PreparedStatement.
 */
class ExcludesTest {

	public interface Skip {}

	public static class Plain extends DynamicSensorsTest.Fixture {
		@Override
		public void m0(String s) {}
	}

	public static class Skipped extends DynamicSensorsTest.Fixture implements Skip {
		@Override
		public void m0(String s) {}
	}

	/** Its name has maven in it, which no sensor is put on. */
	public static class maven_probe {
		public void run(String s) {}
	}

	@BeforeAll
	static void attach() throws Exception {
		DynamicSensorsTest.attach();
	}

	@BeforeEach
	void setUp() {
		Sensor.clearSensors();
		Sensor.protectAll( true );
		Sensor.applyControl( true, Map.of() );
		EventBus.configure( List.of( (EventSink) e -> {} ), 100 );
		Instrumenter.instrument( DynamicSensorsTest.inst, List.of() );
	}

	@AfterEach
	void tearDown() {
		Instrumenter.removeAll();
		Sensor.clearSensors();
		EventBus.shutdown();
	}

	static Sensor anywhere(String name, String method) {
		return new Sensor().name( name ).description( name ).method( method ).capture( "#P0" ).blockWhen( "true" ).scopes( List.of() );
	}

	interface Call { void run(); }

	static boolean stopped(Call call) {
		try {
			call.run();
			return false;
		} catch ( SensorException e ) {
			return true;
		}
	}

	@Test
	void aSensorReachesTheClassesThatExtendTheOneItNames() {
		Instrumenter.add( anywhere( "wide", DynamicSensorsTest.FIXTURE + ".m0" ) );
		Assertions.assertTrue( stopped( () -> new DynamicSensorsTest.Fixture().m0( "x" ) ) );
		Assertions.assertTrue( stopped( () -> new Plain().m0( "x" ) ) );
		Assertions.assertTrue( stopped( () -> new Skipped().m0( "x" ) ), "nothing is left out until it is said" );
	}

	@Test
	void anExcludedTypeIsLeftOutAndTheRestAreNot() {
		Instrumenter.add( anywhere( "narrow", DynamicSensorsTest.FIXTURE + ".m0" ).exclude( Skip.class.getName() ) );
		Assertions.assertTrue( stopped( () -> new DynamicSensorsTest.Fixture().m0( "x" ) ) );
		Assertions.assertTrue( stopped( () -> new Plain().m0( "x" ) ) );
		Assertions.assertFalse( stopped( () -> new Skipped().m0( "x" ) ), "it implements an excluded type" );
	}

	@Test
	void theIgnoresEveryClassGetsStayOnWhenASensorExcludes() {
		Instrumenter.add( anywhere( "probe", maven_probe.class.getName() + ".run" ).exclude( Skip.class.getName() ) );
		Assertions.assertFalse( stopped( () -> new maven_probe().run( "x" ) ), "classes with maven in the name are never instrumented" );
	}

	@Test
	void theIgnoresEveryClassGetsApplyWithoutExcludesToo() {
		Instrumenter.add( anywhere( "probe", maven_probe.class.getName() + ".run" ) );
		Assertions.assertFalse( stopped( () -> new maven_probe().run( "x" ) ) );
	}
}
