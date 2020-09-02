package org.openolly.advice;

import org.openolly.advice.scope.BinaryScope;
import org.openolly.reporting.Trace;

import net.bytebuddy.asm.Advice;

public class TraceAdvice {
	
	public static BinaryScope scope = new BinaryScope();

	@Advice.OnMethodEnter()
	public static void enter() {
		scope.enterScope();
		if ( scope.inOutermostScope() ) {
			Trace.getCurrentTrace().start();
		}
	}

	// Must use onThrowable here to ensure we close the trace in exceptional cases
	@Advice.OnMethodExit(onThrowable = Throwable.class)
	public static void exit() {
		try {
			if ( scope.inOutermostScope() ) {
				Trace.getCurrentTrace().stop();
			}
		} finally {
			scope.leaveScope();
		}
	}

}
