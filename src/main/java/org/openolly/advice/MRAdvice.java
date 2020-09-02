package org.openolly.advice;

import org.openolly.MethodIndexValue;
import org.openolly.Sensor;
import org.openolly.SensorIndexValue;

import net.bytebuddy.asm.Advice;

public class MRAdvice {

	@Advice.OnMethodEnter()
	public static void enter(@SensorIndexValue(value = -1) int sensorIndex,
			@MethodIndexValue(value = -1) int methodIndex) {
		Sensor sensor = Sensor.getSensor(sensorIndex);
		sensor.enterMethodScope(methodIndex);
	}

	@Advice.OnMethodExit(onThrowable = Throwable.class)
	public static void exit(@SensorIndexValue(value = -1) int sensorIndex,
			@MethodIndexValue(value = -1) int methodIndex, @Advice.Origin("#s") String className,
            @Advice.Origin("#m") String methodName, @Advice.This(optional=true) Object obj,
			@Advice.AllArguments Object[] args, @Advice.Return Object ret) throws SensorException {
		Sensor sensor = Sensor.getSensor(sensorIndex);
		try {
			if (sensor.inOutermostMethodScope(methodIndex)) {
				String sig = className + "." + methodName + "()";
				StackTraceElement[] trace = Thread.currentThread().getStackTrace();
				sensor.execute("MRAdvice", sig, obj, args, ret, trace);
			}
		} catch( Throwable t ) {
			if ( !(t instanceof SensorException) ) {
				throw t;
			} else {
				t.printStackTrace();
			}
		} finally {
			sensor.leaveMethodScope(methodIndex);
		}
	}

}
