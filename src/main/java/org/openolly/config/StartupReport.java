package org.openolly.config;

import org.openolly.Sensor;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;

/**
 * Says what this agent started with, as events from the sensor "jot-config", so the dashboard can show what is
 * really running and not what it guesses from files.
 *
 *   lock=monitor | lock=none    -Djot.protect=false locks every rule to report only, and the control file can't undo it
 *   jots=PATH                   the jots file the agent was started with
 *   control=PATH | control=none the control file the agent polls
 *   loaded=NAME                 one for each sensor or rule that was loaded
 *   problem=FILE NAME TEXT      one for each mistake in a .jot file, which left a sensor or rule out
 */
public final class StartupReport {

	static final String SENSOR = "jot-config";

	private StartupReport() {}

	public static void publish( String jotsFile ) {
		say( "lock=" + ( Sensor.isLockedToMonitor() ? "monitor" : "none" ) );
		say( "jots=" + jotsFile );
		String control = System.getProperty( "jot.control" );
		say( "control=" + ( control == null || control.trim().isEmpty() ? "none" : control.trim() ) );
		for ( Sensor s : Sensor.getSensors() ) {
			if ( s.getName() != null ) say( "loaded=" + s.getName() );
		}
		for ( String problem : ConfigReader.getProblems() ) say( "problem=" + problem );
	}

	private static void say( String what ) {
		EventBus.publish( new Event( SENSOR, what, null, Event.Action.OBSERVED, "startup" ) );
	}
}
