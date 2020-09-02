package org.openolly.advice;

import org.openolly.MethodIndexValue;
import org.openolly.Sensor;
import org.openolly.SensorIndexValue;

import net.bytebuddy.asm.Advice;

public class ScopeAdvice {
	
	@Advice.OnMethodEnter()
	public static void enter(@SensorIndexValue(value = -1) int sensorIndex, @MethodIndexValue(value = -1) int scopeIndex) {
		Sensor.enterScopeScope(sensorIndex, scopeIndex);
	}

	// FIXME: Must use onThrowable here to ensure we leave scope in exceptional cases
	// BUT IT'S BREAKING IN CONSTRUCTORS
	@Advice.OnMethodExit()
	public static void exit(@SensorIndexValue(value = -1) int sensorIndex, @MethodIndexValue(value = -1) int scopeIndex) {
		Sensor.leaveScopeScope(sensorIndex, scopeIndex);
	}
	
}
