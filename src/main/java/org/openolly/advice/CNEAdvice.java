package org.openolly.advice;

import org.openolly.MethodIndexValue;
import org.openolly.Sensor;
import org.openolly.SensorIndexValue;

import net.bytebuddy.asm.Advice;

public class CNEAdvice {

	@Advice.OnMethodEnter()
	public static void enter(@SensorIndexValue(value = -1) int sensorIndex,
			@MethodIndexValue(value = -1) int methodIndex) {
		Sensor sensor = Sensor.getSensor(sensorIndex);
		sensor.enterMethodScope(methodIndex);
	}

	@Advice.OnMethodExit()
	public static void exit(@SensorIndexValue(value = -1) int sensorIndex,
			@MethodIndexValue(value = -1) int methodIndex, @Advice.Origin("#t") String className,
			@Advice.Origin("#m") String methodName, @Advice.This(optional = true) Object obj,
			@Advice.AllArguments Object[] args) {
		Sensor sensor = Sensor.getSensor(sensorIndex);
		try {
			if (sensor.inOutermostMethodScope(methodIndex)) {
				String sig = className + "." + methodName + "()";
				StackTraceElement[] trace = Thread.currentThread().getStackTrace();
				sensor.execute("CNEAdvice", sig, obj, args, null, trace);
			}
		} finally {
			sensor.leaveMethodScope(methodIndex);
		}
	}
}
