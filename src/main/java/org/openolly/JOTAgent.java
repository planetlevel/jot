package org.openolly;

import java.lang.instrument.Instrumentation;

import org.openolly.config.ConfigReader;
import org.openolly.reporting.Reporter;

public class JOTAgent {

	public static void premain(String args, Instrumentation inst) {
		System.out.println("[SENSOR] In JOTAgent premain method");
		transform( args, inst );
	}

	public static void agentmain(String args, Instrumentation inst) {
		System.out.println("[SENSOR] In JOTAgent agentmain method");
		transform( args, inst );
	}

	public static void transform(String yaml, Instrumentation inst) {
		try {
			ConfigReader.init(yaml);
			Instrumenter.instrument(inst, Sensor.getSensors());
			new Reporter();
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("[SENSOR] Java Observability Toolkit Installed");
	}
}
