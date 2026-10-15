package org.openolly.advice;

import org.openolly.MethodIndexValue;
import org.openolly.Sensor;
import org.openolly.SensorIndexValue;

import net.bytebuddy.asm.Advice;

/**
 * Scope advice for constructors. Byte Buddy can't catch exceptions around a constructor
 * call, so unlike ScopeAdvice this can't leave the scope when the constructor throws.
 * MethodLocator.healIfLeaked cleans up those leaked scopes.
 */
public class ScopeCtorAdvice {

	@Advice.OnMethodEnter()
	public static void enter(@SensorIndexValue(value = -1) int sensorIndex, @MethodIndexValue(value = -1) int scopeIndex) {
		Sensor.enterScopeScope(sensorIndex, scopeIndex);
	}

	@Advice.OnMethodExit()
	public static void exit(@SensorIndexValue(value = -1) int sensorIndex, @MethodIndexValue(value = -1) int scopeIndex) {
		Sensor.leaveScopeScope(sensorIndex, scopeIndex);
	}

}
