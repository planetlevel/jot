package org.openolly;

import static net.bytebuddy.matcher.ElementMatchers.hasGenericSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.none;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;

import org.openolly.advice.TraceAdvice;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.agent.builder.AgentBuilder.InitializationStrategy;
import net.bytebuddy.agent.builder.AgentBuilder.InstallationListener;
import net.bytebuddy.agent.builder.AgentBuilder.LocationStrategy;
import net.bytebuddy.agent.builder.AgentBuilder.RedefinitionStrategy;
import net.bytebuddy.agent.builder.AgentBuilder.TypeStrategy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.ClassFileLocator;

public class Instrumenter {

	private static Instrumentation inst = null;

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
				.with(InstallationListener.ErrorSuppressing.INSTANCE)  // prevent errors from breaking app
				.with(LocationStrategy.ForClassLoader.STRONG.withFallbackTo(ClassFileLocator.ForClassLoader.ofBootLoader()))
			//	.with(RedefinitionStrategy.RETRANSFORMATION) // for redefine, for java. classes too?
			//	.with(InitializationStrategy.NoOp.INSTANCE) // for redefine
			//	.with(TypeStrategy.Default.REDEFINE) // for redefine
				.disableClassFormatChanges().ignore(none());

			builder = builder
				// add a sensor for every service method to start and stop a trace
				.type(hasGenericSuperType(named("javax.servlet.Servlet")))
				.transform((b, td, cl, m) -> b.visit(Advice.to(TraceAdvice.class).on(named("service").and(isMethod()))));

			for (Sensor sensor : sensors ) {
				System.err.println( "[SENSOR] processing " + sensor );
				builder = sensor.instrument( builder );
			}
			
			builder.installOn(inst);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
