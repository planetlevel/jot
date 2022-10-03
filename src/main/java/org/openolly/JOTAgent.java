package org.openolly;

import java.lang.instrument.Instrumentation;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.Reporter;

import com.google.common.flogger.FluentLogger;

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
		try {
			ConfigReader.init(yaml);
			Instrumenter.instrument(inst, Sensor.getSensors());
			new Reporter();
		} catch (Exception e) {
			//e.printStackTrace();
			logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
		}
		//System.err.println("[SENSOR] Java Observability Toolkit Installed");
		logger.atInfo().log("[SENSOR] Java Observability Toolkit Installed");
	}
}
