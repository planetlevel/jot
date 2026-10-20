package org.openolly;

import static net.bytebuddy.matcher.ElementMatchers.hasGenericSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.none;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.openolly.advice.TraceAdvice;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.utility.JavaModule;
import net.bytebuddy.agent.builder.AgentBuilder.InitializationStrategy;
import net.bytebuddy.agent.builder.AgentBuilder.InstallationListener;
import net.bytebuddy.agent.builder.AgentBuilder.LocationStrategy;
import net.bytebuddy.agent.builder.AgentBuilder.RedefinitionStrategy;
import net.bytebuddy.agent.builder.AgentBuilder.TypeStrategy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.ClassFileLocator;

import org.openolly.log.FluentLogger;

public class Instrumenter {
	
	private static final FluentLogger logger = FluentLogger.forEnclosingClass();

	private static Instrumentation inst = null;

	// -Djot.verbose=true writes instrumentation errors to the agent's log, see -Djot.log, and they are otherwise suppressed
	private static final boolean VERBOSE = Boolean.getBoolean("jot.verbose");
	// on unless -Djot.retransform=false, see the comment where it is used
	private static final boolean RETRANSFORM = !"false".equalsIgnoreCase(System.getProperty("jot.retransform"));

	private static class ErrorLogger extends AgentBuilder.Listener.Adapter {
		@Override
		public void onError(String typeName, ClassLoader classLoader, JavaModule module, boolean loaded, Throwable throwable) {
			logger.atSevere().withCause(throwable).log("[JOT] Error instrumenting %s", typeName);
		}
	}

	public static void instrument(Instrumentation inst, Sensor sensor ) {
		List<Sensor> list = new ArrayList<Sensor>();
		list.add( sensor );
		instrument( inst, list );
	}
	
	public static void instrument(Instrumentation inst, List<Sensor> sensors) {
		Instrumenter.inst = inst;

		try {
			AgentBuilder builder = new AgentBuilder.Default()
			//	.with(AgentBuilder.Listener.StreamWriting.toSystemError())
			//	.with(AgentBuilder.Listener.StreamWriting.toSystemError().withErrorsOnly())
			//	.with(AgentBuilder.Listener.StreamWriting.toSystemError().withTransformationsOnly())
				.with(InstallationListener.ErrorSuppressing.INSTANCE)  // prevent errors from breaking app, and nothing goes to the application's console
				.with(VERBOSE ? new ErrorLogger() : AgentBuilder.Listener.NoOp.INSTANCE)
				.with(new JotScopeListener())      // sensors must not see JOT reading class files while it decides what to instrument
				.with(LocationStrategy.ForClassLoader.STRONG.withFallbackTo(ClassFileLocator.ForClassLoader.ofBootLoader()))
			//	.with(RedefinitionStrategy.RETRANSFORMATION) // for redefine, for java. classes too?
			//	.with(InitializationStrategy.NoOp.INSTANCE) // for redefine
			//	.with(TypeStrategy.Default.REDEFINE) // for redefine
				.disableClassFormatChanges().ignore(none());

			// The JVM has already loaded some classes, such as java.io.File and MessageDigest, by the time the agent starts.
			// Those are only instrumented if they are transformed again, which costs a little at startup, so it is on
			// unless -Djot.retransform=false.
			if ( RETRANSFORM ) {
				builder = builder.with( AgentBuilder.RedefinitionStrategy.RETRANSFORMATION );
			}

			builder = builder
				// add a sensor for every service method to start and stop a trace
				.type(hasGenericSuperType(namedOneOf("javax.servlet.Servlet", "jakarta.servlet.Servlet")))
				.transform((b, td, cl, m, pd) -> b.visit(Advice.to(TraceAdvice.class).on(named("service").and(isMethod()))));

			for (Sensor sensor : sensors ) {
				//System.err.println( "[SENSOR] processing " + sensor );
				logger.atFine().log("[SENSOR] processing " + sensor);
				builder = sensor.instrument( builder );
			}
			
			// the application's entry points, once for all the JOTs that are scoped to it
			builder = AppScope.instrument( builder );

			builder.installOn(inst);
		} catch (Exception e) {
			//e.printStackTrace();
			logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
		}
	}

}
