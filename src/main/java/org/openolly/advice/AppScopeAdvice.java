package org.openolly.advice;

import org.openolly.AppScope;

import net.bytebuddy.asm.Advice;

/** Enters the application scope when an entry point starts and leaves it when it ends, however it ends. */
public class AppScopeAdvice {

	@Advice.OnMethodEnter()
	public static void enter(@Advice.Origin("#t.#m") String entry) {
		AppScope.enter( entry );
	}

	// onThrowable ensures we leave the scope when the method exits exceptionally
	@Advice.OnMethodExit(onThrowable = Throwable.class)
	public static void exit() {
		AppScope.leave();
	}
}
