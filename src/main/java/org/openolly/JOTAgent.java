package org.openolly;

import java.lang.instrument.Instrumentation;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.openolly.config.ConfigReader;
import org.openolly.config.ControlFile;
import org.openolly.config.StartupReport;
import org.openolly.reporting.EventBus;

import org.openolly.log.FluentLogger;

public class JOTAgent {
	
	private static final FluentLogger logger = FluentLogger.forEnclosingClass();
	
	public static void premain(String args, Instrumentation inst) {
		//System.out.println("[SENSOR] In JOTAgent premain method");
		transform( args, inst );
	}

	public static void agentmain(String args, Instrumentation inst) {
		//System.out.println("[SENSOR] In JOTAgent agentmain method");
		transform( args, inst );
	}

	public static void transform(String yaml, Instrumentation inst) {
		JotScope.enter();
		try {
			yaml = ConfigReader.locate(yaml);
			if ( yaml != null && System.getProperty( "jot.dir" ) == null ) {
				// what the agent writes goes beside the file it reads, whatever directory the application was started in
				java.io.File folder = new java.io.File( yaml ).getAbsoluteFile().getParentFile();
				System.setProperty( "jot.dir", folder.getName().equals( ".jot" ) ? folder.getPath() : new java.io.File( folder, ".jot" ).getPath() );
			}
			EventBus.configureFromSystemProperties();
			ConfigReader.init(yaml);
			Instrumenter.instrument(inst, Sensor.getSensors());
			ControlFile.startFromSystemProperties();
			StartupReport.publish( yaml );
		} catch (Exception e) {
			//e.printStackTrace();
			logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
		} finally {
			JotScope.exit();
		}
		//System.err.println("[SENSOR] Java Observability Toolkit Installed");
		logger.atInfo().log("[SENSOR] Java Observability Toolkit Installed");
	}
}
