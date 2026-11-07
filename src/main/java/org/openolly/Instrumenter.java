package org.openolly;

import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.none;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.openolly.advice.TraceAdvice;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.agent.builder.ResettableClassFileTransformer;
import net.bytebuddy.utility.JavaModule;
import net.bytebuddy.agent.builder.AgentBuilder.InstallationListener;
import net.bytebuddy.agent.builder.AgentBuilder.LocationStrategy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.ClassFileLocator;

import org.openolly.log.FluentLogger;

/**
 * Puts sensors on the application's classes, and takes them off again while it runs.
 *
 * Each sensor has a transformer of its own, so one can be removed without touching the others. The application's entry points
 * and the servlet trace, which every sensor shares, have one more that is never removed. Adding a sensor installs its
 * transformer and, unless -Djot.retransform=false, transforms the classes that are already loaded. Removing a sensor retires
 * it, so that it does nothing at once, and then removes its transformer and transforms the loaded classes back, which takes
 * its advice out. A call that was already running keeps going and finds the retired sensor, which ignores it, see Sensor.getSensor.
 *
 * All of it is synchronized, so a reload that is still working finishes before the next begins.
 */
public class Instrumenter {

	private static final FluentLogger logger = FluentLogger.forEnclosingClass();

	private static Instrumentation inst = null;
	// the entry points and the trace, put on once
	private static ResettableClassFileTransformer shared = null;
	// the sensors that are on, by id and in the order they were added
	private static final Map<Integer, ResettableClassFileTransformer> installed = new LinkedHashMap<Integer, ResettableClassFileTransformer>();

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

	/** Puts every sensor in the list that isn't on yet, and the shared advice, on. */
	public static synchronized void instrument(Instrumentation inst, List<Sensor> sensors) {
		Instrumenter.inst = inst;
		apply( List.of(), sensors );
	}

	/** Puts one sensor on. Returns false if it was already on or couldn't be put on, and then it is not on at all. */
	public static synchronized boolean add(Sensor sensor) {
		return apply( List.of(), List.of( sensor ) ) > 0;
	}

	/**
	 * Takes the first list off and puts the second on, all at once. Returns how many were put on. Removing comes first so a
	 * sensor that is edited, off and on again under the same name, is never on twice.
	 */
	public static synchronized int apply(List<Sensor> off, List<Sensor> on) {
		Loaded loaded = new Loaded();
		for ( Sensor sensor : off ) removeOne( sensor, loaded );
		int added = 0;
		for ( Sensor sensor : on ) {
			if ( addOne( sensor, loaded ) ) added++;
		}
		// The shared advice must wrap the sensors, so it starts the trace before a sensor on the same method looks at it, and ends
		// it after. Advice goes around whatever was put on before it, so the shared advice has to be put on after every sensor.
		if ( added > 0 || shared == null ) reseatShared( loaded );
		return added;
	}

	private static boolean addOne(Sensor sensor, Loaded loaded) {
		if ( inst == null || sensor.isRetired() || installed.containsKey( sensor.getIndex() ) ) return false;
		try {
			//System.err.println( "[SENSOR] processing " + sensor );
			logger.atFine().log("[SENSOR] processing " + sensor);
			ResettableClassFileTransformer transformer = sensor.instrument( builder( loaded, sensor.targetClassNames() ) ).installOn( inst );
			installed.put( sensor.getIndex(), transformer );
			return true;
		} catch (Throwable e) {
			//e.printStackTrace();
			logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
			return false;
		}
	}

	/**
	 * Takes one sensor off. It stops at once, and its advice is taken out of the loaded classes. Returns false if it
	 * wasn't on. A sensor that fails to come off is still retired, so what remains of its advice does nothing.
	 */
	public static synchronized boolean remove(Sensor sensor) {
		return removeOne( sensor, new Loaded() );
	}

	private static boolean removeOne(Sensor sensor, Loaded loaded) {
		sensor.retire();
		ResettableClassFileTransformer transformer = installed.remove( sensor.getIndex() );
		if ( transformer == null ) return false;
		loaded.reset( transformer, sensor.targetClassNames() );
		return true;
	}

	/** Takes every sensor and the shared advice off, which puts the loaded classes back as they were. For tests, and for when the agent is done. */
	public static synchronized void removeAll() {
		Loaded loaded = new Loaded();
		for ( Sensor sensor : new ArrayList<Sensor>( Sensor.getSensors() ) ) removeOne( sensor, loaded );
		for ( Integer id : new ArrayList<Integer>( installed.keySet() ) ) {
			Sensor sensor = Sensor.getSensor( id );
			if ( sensor != null ) removeOne( sensor, loaded );
		}
		if ( shared != null ) {
			loaded.reset( shared, sharedTargets() );
			shared = null;
		}
	}

	/** True if this sensor's advice is installed. */
	public static synchronized boolean isInstalled(Sensor sensor) {
		return installed.containsKey( sensor.getIndex() );
	}

	/** How many sensors are installed. */
	public static synchronized int installedCount() {
		return installed.size();
	}

	/** A builder that puts its advice on the classes that load from now on, and on the loaded classes that are, or extend, one of these names. */
	private static AgentBuilder builder(Loaded loaded, java.util.Set<String> names) {
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
		// unless -Djot.retransform=false. A sensor added later gets the same, and has to, because the classes it targets are loaded by then.
		if ( RETRANSFORM ) {
			builder = builder.with( AgentBuilder.RedefinitionStrategy.RETRANSFORMATION ).with( loaded.discovery( names ) );
		}
		return Sensor.globalIgnores( builder );
	}

	/**
	 * Puts the shared advice on again, after everything else. The new one goes on before the old comes off, so there is no
	 * moment without it. For a moment a method has it twice, which is harmless because both only count how deep they are.
	 */
	private static void reseatShared(Loaded loaded) {
		reseatShared( loaded, sharedTargets() );
	}

	/** oldTargets are the classes the shared advice that is on now can be in, which is where the old one has to come off. */
	private static boolean reseatShared(Loaded loaded, java.util.Set<String> oldTargets) {
		ResettableClassFileTransformer old = shared;
		if ( !installShared( loaded ) ) return false;
		if ( old == null ) return true;
		java.util.Set<String> names = sharedTargets();
		if ( names != null && oldTargets != null ) names.addAll( oldTargets );
		loaded.reset( old, names == null || oldTargets == null ? null : names );
		return true;
	}

	/**
	 * Changes the application's entry points while the application runs. The new list is used at once by the sensors that look
	 * at it, and the advice on the entry points is put on again for it. A call already inside an entry point keeps the advice it
	 * started with, because the advice is part of the method it is running, so it ends the way it began and the count of how deep
	 * a thread is stays right. Only calls that begin after are held to the new list. Returns false if it could not be put on, in
	 * which case the entry points stay as they were.
	 */
	public static synchronized boolean changeEntries(List<String> entries) {
		List<String> before = AppScope.signatures();
		if ( before.equals( entries ) ) return true;
		java.util.Set<String> oldTargets = sharedTargets();
		AppScope.configure( entries );
		if ( inst == null ) return true;
		if ( reseatShared( new Loaded(), oldTargets ) ) return true;
		AppScope.configure( before );
		return false;
	}

	/** The classes the shared advice can apply to, or null for any. */
	private static java.util.Set<String> sharedTargets() {
		java.util.Set<String> names = new java.util.LinkedHashSet<String>( List.of( "javax.servlet.Servlet", "jakarta.servlet.Servlet" ) );
		for ( MethodLocator entry : AppScope.entries() ) {
			if ( entry.isAnnotation() ) return null;
			names.add( entry.className() );
		}
		return names;
	}

	/**
	 * The classes the JVM has loaded, taken once for a whole change. A sensor is only looked for in the classes that are, or
	 * extend or implement, one it names, so putting on or taking off a sensor costs about what it matches and not the number
	 * of classes the application has loaded. Without this, fifty sensors would each go through every class.
	 */
	private static class Loaded {
		private Map<String, List<Class<?>>> byName = null;

		private Map<String, List<Class<?>>> index() {
			if ( byName != null ) return byName;
			byName = new java.util.HashMap<String, List<Class<?>>>();
			for ( Class<?> type : inst.getAllLoadedClasses() ) {
				try {
					if ( !inst.isModifiableClass( type ) ) continue;
					java.util.Set<String> names = new java.util.HashSet<String>();
					collect( type, names );
					for ( String name : names ) byName.computeIfAbsent( name, k -> new ArrayList<Class<?>>() ).add( type );
				} catch ( Throwable e ) {
					// a class whose supertypes can't be read is left out, it is still transformed when it loads
				}
			}
			return byName;
		}

		private static void collect(Class<?> type, java.util.Set<String> names) {
			if ( type == null || !names.add( type.getName() ) ) return;
			collect( type.getSuperclass(), names );
			for ( Class<?> face : type.getInterfaces() ) collect( face, names );
		}

		AgentBuilder.RedefinitionStrategy.DiscoveryStrategy discovery(java.util.Set<String> names) {
			if ( names == null ) return AgentBuilder.RedefinitionStrategy.DiscoveryStrategy.SinglePass.INSTANCE;
			java.util.Set<Class<?>> found = new java.util.LinkedHashSet<Class<?>>();
			for ( String name : names ) {
				List<Class<?>> list = index().get( name );
				if ( list != null ) found.addAll( list );
			}
			return new AgentBuilder.RedefinitionStrategy.DiscoveryStrategy.Explicit( found.toArray( new Class<?>[0] ) );
		}

		void reset(ResettableClassFileTransformer transformer, java.util.Set<String> names) {
			try {
				// without retransformation the classes that are loaded keep the advice, which is harmless now that the sensor is retired
				if ( RETRANSFORM ) transformer.reset( inst, AgentBuilder.RedefinitionStrategy.RETRANSFORMATION, discovery( names ) );
				else transformer.reset( inst, AgentBuilder.RedefinitionStrategy.DISABLED );
			} catch (Throwable e) {
				logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
			}
		}
	}

	private static boolean installShared(Loaded loaded) {
		try {
			AgentBuilder builder = builder( loaded, sharedTargets() )
				// add a sensor for every service method to start and stop a trace
				.type(TypeHierarchy.extending("javax.servlet.Servlet", "jakarta.servlet.Servlet"))
				.transform((b, td, cl, m, pd) -> b.visit(Advice.to(TraceAdvice.class).on(named("service").and(isMethod()))));

			// the application's entry points, once for all the JOTs that are scoped to it. They are put on first so they run first on the way in,
			// which starts the trace of the entry point before the sensors on that same method record anything, and last on the way out
			builder = AppScope.instrument( builder );
			shared = builder.installOn(inst);
			return true;
		} catch (Throwable e) {
			//e.printStackTrace();
			logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
			return false;
		}
	}

}
