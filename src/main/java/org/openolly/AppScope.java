package org.openolly;

import static net.bytebuddy.matcher.ElementMatchers.isMethod;

import java.util.ArrayList;
import java.util.List;

import org.openolly.advice.AppScopeAdvice;
import org.openolly.advice.scope.BinaryScope;

import com.google.common.flogger.FluentLogger;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

/**
 * The application as one scope. The jots file lists the entry points, the places the application starts running, like a servlet's
 * service method, a method carrying a framework's annotation, or a main. A JOT that doesn't say its own scopes applies only while one
 * of them is running on the thread, so it leaves out startup, background threads and anything else that isn't the application at
 * work, without every JOT saying so. A JOT that does write scopes uses those instead, and scopes: [] means anywhere.
 *
 *   app:
 *     entry:
 *     - javax.servlet.Servlet.service
 *     - "@dev.langchain4j.agent.tool.Tool"
 *
 * An entry is a method, or an annotation, which is every method that carries it and every method of a class that does. Without an
 * entry list the servlet service methods are used, and entry: [] leaves no application scope, so JOTs apply everywhere.
 *
 * It is not what the platform does inside a request, loading classes and compiling pages, see PlatformWork for that.
 */
public final class AppScope {

	private static final FluentLogger logger = FluentLogger.forEnclosingClass();

	/** The entry points when the jots file doesn't say. */
	public static final List<String> DEFAULT_ENTRY = List.of( "javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service" );

	private static volatile List<MethodLocator> entries = List.of();
	private static final BinaryScope depth = new BinaryScope();

	private AppScope() {}

	/** Sets the entry points, from the jots file. Null is the default and an empty list means there is no application scope. */
	public static void configure(List<String> entry) {
		List<MethodLocator> made = new ArrayList<MethodLocator>();
		for ( String signature : entry == null ? DEFAULT_ENTRY : entry ) {
			made.add( new MethodLocator( signature ) );
		}
		entries = List.copyOf( made );
	}

	public static List<MethodLocator> entries() {
		return entries;
	}

	/** True if there are entry points, which is when a JOT without scopes of its own is limited to the application. */
	public static boolean configured() {
		return !entries.isEmpty();
	}

	/** True while an entry point is running on this thread. */
	public static boolean active() {
		return depth.inScope();
	}

	public static void enter() {
		depth.enterScope();
	}

	public static void leave() {
		depth.leaveScope();
	}

	/** Puts the advice on every entry point. One advice for all of them, however many JOTs use the application scope. */
	public static AgentBuilder instrument(AgentBuilder builder) {
		for ( MethodLocator entry : entries ) {
			logger.atWarning().log( "APP SCOPE " + ( entry.isAnnotation() ? "@" + entry.annotationName() : entry.className() + " -> " + entry.methodName() ) );
			if ( entry.isConstructor() ) {
				logger.atWarning().log( "WARNING: " + entry.className() + " is a constructor, which can't be an entry point of the application. Ignoring" );
				continue;
			}
			try {
				builder = builder
					.type( Sensor.typeMatcher( entry ) )
					.transform( (b, td, cl, m, pd) -> b.visit( Advice.to( AppScopeAdvice.class ).on( isMethod().and( Sensor.methodMatcher( entry ) ) ) ) );
			} catch ( Exception e ) {
				logger.atWarning().log( "WARNING: Error instrumenting the application scope: " + e.getMessage() );
			}
		}
		return builder;
	}
}
