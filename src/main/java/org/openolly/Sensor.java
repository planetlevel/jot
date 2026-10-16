package org.openolly;

import static net.bytebuddy.matcher.ElementMatchers.failSafe;
import static net.bytebuddy.matcher.ElementMatchers.hasGenericSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.nameContains;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.openolly.advice.CEAdvice;
import org.openolly.advice.CNEAdvice;
import org.openolly.advice.MRAdvice;
import org.openolly.advice.MVEAdvice;
import org.openolly.advice.MVNEAdvice;
import org.openolly.advice.ScopeAdvice;
import org.openolly.advice.ScopeCtorWrapper;
import org.openolly.advice.SensorException;
import org.openolly.reporting.Event;
import org.openolly.reporting.EventBus;

import com.google.common.flogger.FluentLogger;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;

public class Sensor {

	private static final FluentLogger logger = FluentLogger.forEnclosingClass();
	private static List<Sensor> sensors = new ArrayList<Sensor>();

	// an index to use to look up the right Sensor from within an instrumented method
	private int index;
	
	private String name = null;
	private String description = null;
	private List<MethodLocator> methods = new ArrayList<MethodLocator>();
	private List<MethodLocator> scopes = new ArrayList<MethodLocator>();
	private List<MethodLocator> excludes = new ArrayList<MethodLocator>();
	private List<Expression> captures = new ArrayList<Expression>();
	private List<Matcher> negativeMatchers = new ArrayList<Matcher>();
	private List<Matcher> positiveMatchers = new ArrayList<Matcher>();
	private String exception = null;
	private boolean debug = false;
	// false stops this rule from being enforced, so it only reports. Null leaves it to jot.enforce
	private Boolean enforce = null;

	// -Djot.enforce=false makes every rule with an exception only report, nothing is stopped
	private static volatile boolean enforceAll = !"false".equalsIgnoreCase( System.getProperty( "jot.enforce" ) );
	private boolean hasReturn = false;

	private Pattern namePattern = Pattern.compile( "([a-z][a-z0-9]*\\-)*[a-z][a-z0-9]*");
	private Pattern descriptionPattern = Pattern.compile( "^.*$");
	private Pattern methodPattern = Pattern.compile( "^(!)?([\\p{L}_$][\\p{L}\\p{N}_$]*\\.)*(<init>|[\\p{L}_$][\\p{L}\\p{N}_$]*)$");
	private Pattern capturePattern = Pattern.compile( "^.*$");
	private Pattern exceptionPattern = Pattern.compile( "^.*$");

	public Sensor() {
		sensors.add( this );
		this.index = sensors.indexOf(this);
	}
	
	public static boolean exists(String name) {
		for ( Sensor s : sensors ) {
			if ( name != null && name.equals( s.getName() ) ) {
				return true;
			}
		}
		return false;
	}

	public static Sensor getSensor(int sensorIndex) {
		return sensors.get( sensorIndex );
	}

	public static List<Sensor> getSensors() {
		return Collections.unmodifiableList(sensors);
	}

	public static void clearSensors() {
		sensors.clear();
	}

	// a sensor that blocks reports the block, not each thing it captured on the way
	private void publishObserved(Event event) {
		if ( getException() == null ) EventBus.publish( event );
	}

	/**
	 * Walking the stack is expensive, so it is only done once we know the sensor will really run,
	 * not for every call to a method that happens to have a sensor on it.
	 */
	public List<Object> execute(String advice, String caller, Object obj, Object[] params, Object ret) {
		return execute( advice, caller, obj, params, ret, null );
	}

	/**
	 * The current stack with JOT's own frames removed, so it looks like it was captured by advice
	 * inlined in the instrumented method. [0] is Thread.getStackTrace, [1] is the instrumented method.
	 */
	static StackTraceElement[] currentStack() {
		StackTraceElement[] full = Thread.currentThread().getStackTrace();
		String self = Sensor.class.getName();
		int skip = 1;
		while ( skip < full.length && full[skip].getClassName().equals( self ) ) skip++;
		StackTraceElement[] stack = new StackTraceElement[full.length - skip + 1];
		stack[0] = full[0];
		System.arraycopy( full, skip, stack, 1, full.length - skip );
		return stack;
	}

	public List<Object> execute(String advice, String caller, Object obj, Object[] params, Object ret, StackTraceElement[] stack) {			

		// no sensor fires while JOT's own code is running, in this sensor or any other
		if ( JotScope.active() ) return new ArrayList<Object>();

		// return results for making tests easier
		List<Object> results = new ArrayList<Object>();
		try {
			JotScope.enter();
			
			// if there are scopes, and none are in scope, quit
			if ( !scopes.isEmpty() ) {
				boolean inScope = false;
				for ( MethodLocator scope : scopes ) {
					inScope |= ( scope.inScope() );
				}
				if ( !inScope ) return results;
			}
	
			if ( stack == null && ( !captures.isEmpty() || getException() != null ) ) stack = currentStack();

			for (Expression capture : captures) {
				try {
					Object o = capture.execute(obj, params, ret, caller, stack);
					
					if ( o instanceof Collection ) {
						for ( Object item : (Collection)o ) {
							String safe = SafeString.format( item, debug );
							boolean matched = Matcher.eval( safe, getPositiveMatchers(), getNegativeMatchers() );
							if ( matched ) {
								String cleaned = StringUtils.normalizeSpace( safe );
								Event event = new Event(getName(), cleaned, stack);
								publishObserved( event );
								// logger.atWarning().log( "[JOT %s] %s", this, event );
		 						results.add(safe);
							}
						}
					} else {
						String safe = SafeString.format( o, debug );
						boolean matched = Matcher.eval( safe, getPositiveMatchers(), getNegativeMatchers() );
						if ( matched ) {
							String cleaned = StringUtils.normalizeSpace( safe );
							Event event = new Event(getName(), cleaned, stack);
								publishObserved( event );
							// logger.atWarning().log( "[JOT %s] %s", this, event );
	 						results.add(safe);
						}
					}
					
				} catch( Exception e ) {
					logger.atWarning().log( "[JOT %s] Error running capture (%s) %s", this, capture, e.getMessage() );
					//e.printStackTrace();
					logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
				}
			}

			// if there are either results or zero captures, generate exceptions if any
			if ( getException() != null ) {
				if ( captures.isEmpty() || !results.isEmpty() ) {
					String details = results.stream().map( String::valueOf ).collect( Collectors.joining( " | " ) );
					if ( isEnforced() ) {
						SensorException e = new SensorException( getException() );
						EventBus.publish( new Event( getName(), details, stack, Event.Action.BLOCKED, getException() ) );
						throw e;
					}
					// not enforced, so say what would have been stopped and let the call go ahead
					EventBus.publish( new Event( getName(), details, stack, Event.Action.MONITORED, getException() ) );
				}
			}			
		} finally {
			JotScope.exit();
		}
		return results;
	}

	public String toString() {
		return getName();
	}
	
//================= parsing	
	
	public Sensor name(String value) {
		if ( value == null ) {
			logger.atWarning().log( "[JOT %s] YAML error: name was missing. Continuing.", this );
			return this;
		}		
		if (!namePattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed name (" + value + ") must match " + namePattern.pattern() + ". Continuing", this );
		}
		name = value;
		return this;
	}

	public Sensor description(String value) {
		if ( value == null ) {
			return this;
		}		
		if (!descriptionPattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed description (" + value + ") must match " + descriptionPattern.pattern() + ". Continuing", this );
		}
		description = value;
		return this;
	}


	public Sensor method(String value) {
		if ( value == null ) {
			logger.atWarning().log( "[JOT %s] YAML error: at least one method is required. Continuing", this );
			return this;
		}		
		if (!methodPattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed method (" + value + ") must match " + methodPattern.pattern() + ". Continuing", this );
		}
		addMethod( value );
		String alias = jakartaAlias( value );
		if ( alias != null ) addMethod( alias );
		return this;
	}

	private void addMethod(String value) {
		for ( MethodLocator existing : methods ) {
			if ( sameSignature( existing, value ) ) return;
		}
		MethodLocator loc = new MethodLocator( value );
		methods.add( loc );
		loc.setIndex( methods.indexOf( loc ) );
	}

	private static boolean sameSignature(MethodLocator loc, String sig) {
		MethodLocator other = new MethodLocator( sig );
		return java.util.Objects.equals( loc.className(), other.className() )
				&& java.util.Objects.equals( loc.methodName(), other.methodName() );
	}

	/**
	 * The packages Jakarta EE 9 renamed from javax to jakarta. Applications on Tomcat 9 and earlier use
	 * the javax names and Tomcat 10 and later the jakarta ones. Most javax packages are part of the JDK
	 * and were not renamed, such as javax.crypto, javax.naming and javax.sql, so this is a list and not a rule.
	 */
	private static final String[] JAKARTA_PACKAGES = { "servlet", "el", "websocket", "persistence", "validation",
			"ws.rs", "mail", "jms", "transaction", "ejb", "faces", "inject", "enterprise", "json", "jws",
			"xml.bind", "xml.ws", "activation", "annotation", "interceptor", "batch", "resource",
			"security.enterprise", "security.auth.message" };

	/** Packages under a renamed one that belong to the JDK and keep their javax name. */
	private static final String[] STAYS_JAVAX = { "transaction.xa", "annotation.processing" };

	/**
	 * The jakarta name for a javax name, and the other way round, so a JOT written for either works on
	 * both. Returns null if the name isn't in a package that was renamed.
	 */
	static String jakartaAlias(String sig) {
		if ( sig == null ) return null;
		String from;
		String to;
		if ( sig.startsWith( "javax." ) ) {
			from = "javax.";
			to = "jakarta.";
		} else if ( sig.startsWith( "jakarta." ) ) {
			from = "jakarta.";
			to = "javax.";
		} else {
			return null;
		}
		String rest = sig.substring( from.length() );
		for ( String stays : STAYS_JAVAX ) {
			if ( rest.startsWith( stays + "." ) ) return null;
		}
		for ( String pkg : JAKARTA_PACKAGES ) {
			if ( rest.startsWith( pkg + "." ) ) return to + rest;
		}
		return null;
	}
	public Sensor methods( List<String> list ) {
		if ( list == null || list.isEmpty() ) {
			return this;
		}		
		for ( String value : list ) {
			method( value );
		}
		return this;
	}

	public Sensor scope(String value) {
		if ( value == null ) {
			return this;
		}		
		boolean negative = false;
		if ( value.startsWith( "!" ) ) {
			negative = true;
			value = value.substring(1);
		}
		if (!methodPattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed scope (" + value + ") must match " + methodPattern.pattern(), this );
		}
		addScope( value, negative );
		// a negative scope isn't aliased, "not in javax" or "not in jakarta" would be true inside either
		String alias = negative ? null : jakartaAlias( value );
		if ( alias != null ) addScope( alias, false );
		return this;
	}

	private void addScope(String value, boolean negative) {
		for ( MethodLocator existing : scopes ) {
			if ( sameSignature( existing, value ) && existing.isNegative() == negative ) return;
		}
		MethodLocator loc = new MethodLocator( value, negative );
		scopes.add( loc );
		loc.setIndex( scopes.indexOf( loc ) );
	}

	public Sensor scopes( List<String> list ) {
		if ( list == null || list.isEmpty() ) {
			return this;
		}		
		for ( String s : list ) {
			scope( s );
		}
		return this;
	}
	
	public Sensor exclude(String value) {
		if ( value == null ) {
			return this;
		}		
		if (!methodPattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed exclude (" + value + ") must match " + methodPattern.pattern(), this );
		}
		excludes.add(new MethodLocator(value, null));
		return this;
	}
	
	public Sensor excludes( List<String> list ) {
		if ( list == null || list.isEmpty() ) {
			return this;
		}		
		for ( String s : list ) {
			exclude( s );
		}
		return this;
	}

	public Sensor capture(String value) {
		if ( value == null ) {
			return this;
		}		
		if (!capturePattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed capture (" + value + ") must match " + capturePattern.pattern(), this );
		}
		try {
			Expression exp = new Expression(value);
			if ( value.contains( "#RET" ) ) {
				hasReturn = true;
			}
			captures.add( exp );
		} catch( Exception e ) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed capture (" + value + "): " + e.getMessage(), this );
		}
		return this;
	}

	public Sensor captures( List<String> list ) {
		if ( list == null || list.isEmpty() ) {
			return this;
		}		
		for ( String s : list ) {
			capture( s );
		}
		return this;
	}

	public Sensor matcher(String value) {
		try {
			if ( value == null ) {
				return this;
			}
			if ( value.startsWith( "!" ) ) {
				value = value.substring(1);
				Matcher matcher = new Matcher( value, true );
				negativeMatchers.add( matcher );
			} else {
				Matcher matcher = new Matcher( value, false );
				positiveMatchers.add( matcher );
			}
		} catch( Exception e ) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed matcher (" + value + "): " + e.getMessage(), this );
		}		
		return this;
	}

	public Sensor matchers( List<String> list ) {
		if ( list == null || list.isEmpty() ) {
			return this;
		}		
		for ( String s : list ) {
			matcher( s );
		}
		return this;
	}

	public Sensor exception(String value) {
		if ( value == null ) {
			return this;
		}		
		if (!exceptionPattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed exception (" + value + ") must match " + exceptionPattern.pattern(), this );
		}
		exception = value;
		return this;
	}
	
	public Sensor debug( boolean value ) {
		debug = value;
		return this;
	}

	/**
	 * Setting this to false makes the rule report violations without stopping them. A rule can only turn its
	 * own enforcement off. It can't turn it on when jot.enforce is false, which switches off every rule.
	 */
	public Sensor enforce( Boolean value ) {
		enforce = value;
		return this;
	}

	/** True if a violation of this rule stops the call. */
	public boolean isEnforced() {
		return enforceAll && !Boolean.FALSE.equals( enforce );
	}

	/** Set whether rules are enforced at all, the same as -Djot.enforce. */
	public static void enforceAll( boolean value ) {
		enforceAll = value;
	}

	
	
	// ===========

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public List<MethodLocator> getMethods() {
		return methods;
	}

	public List<MethodLocator> getScopes() {
		return scopes;
	}

	public List<MethodLocator> getExcludes() {
		return excludes;
	}

	public List<Expression> getCaptures() {
		return captures;
	}
	
	public List<Matcher> getPositiveMatchers() {
		return positiveMatchers;
	}
	
	public List<Matcher> getNegativeMatchers() {
		return negativeMatchers;
	}
	
	public String getException() {
		return exception;
	}

	public boolean hasException() {
		return exception != null;
	}
	
	public int getIndex() {
		return index;
	}
	
	public MethodLocator getMethodScope( int index ) {
		return methods.get( index );
	}
	
	public boolean getDebug() {
		return debug;
	}
	
	public boolean hasReturn() {
		return hasReturn;
	}

//==============

	public static void enterMethodScope( int sensorIndex, int methodIndex ) {
		getSensor( sensorIndex ).enterMethodScope( methodIndex );
	}
	
	public static void leaveMethodScope( int sensorIndex, int methodIndex ) {
		getSensor( sensorIndex ).leaveMethodScope( methodIndex );
	}
	
	public int methodScopeValue(int methodIndex) {
		MethodLocator loc = methods.get(methodIndex);
		return loc.scopeValue();
	}

	public void enterMethodScope(int methodIndex) {
		MethodLocator loc = methods.get(methodIndex);
		if ( debug ) logger.atFine().log( "[JOT %s] METHOD SCOPE ["+methodIndex+"] + " + loc.scopeValue() +" >> "+ getName() + " " + (loc.scopeValue() + 1), this );
		loc.enterScope();
	}

	public void leaveMethodScope(int methodIndex) {
		MethodLocator loc = methods.get(methodIndex);
		loc.leaveScope();
		if ( debug ) logger.atFine().log( "[JOT %s] METHOD SCOPE ["+methodIndex+"] - " + (loc.scopeValue() + 1) + " >> "+ getName() + " " + loc.scopeValue(), this );
	}
	
	public boolean inOutermostMethodScope(int methodIndex) {
		MethodLocator loc = methods.get(methodIndex);
		return loc.inOutermostScope();
	}
	
//=========== FIXME: ScopeScope is a stupid name
	
	public static void enterScopeScope( int sensorIndex, int scopeIndex ) {
		getSensor( sensorIndex ).enterScopeScope( scopeIndex );
	}
	
	public static void leaveScopeScope( int sensorIndex, int scopeIndex ) {
		getSensor( sensorIndex ).leaveScopeScope( scopeIndex );
	}
		
	public int scopeScopeValue(int scopeIndex) {
		MethodLocator loc = scopes.get(scopeIndex);
		return loc.scopeValue();
	}

	public void enterScopeScope(int scopeIndex) {
		MethodLocator loc = scopes.get(scopeIndex);
		if ( debug ) logger.atFine().log( "[JOT %s] SCOPE SCOPE" + loc.scopeValue() +" >> "+ getName(), this);
		loc.enterScope();
	}

	public void leaveScopeScope(int scopeIndex) {
		MethodLocator loc = scopes.get(scopeIndex);
		loc.leaveScope();
		if ( debug ) logger.atFine().log( "[JOT %s] SCOPE SCOPE" + loc.scopeValue() +" << "+ getName(), this);
	}
	
	public boolean inOutermostScopeScope(int scopeIndex) {
		MethodLocator loc = scopes.get(scopeIndex);
		return loc.inOutermostScope();
	}
	

	public AgentBuilder instrument(AgentBuilder builder ) {
				
		// global class ignores
		builder = builder
		.ignore(nameContains("maven"))
		.ignore(nameContains("codehaus"))
		.ignore(nameStartsWith("shaded"))
		.ignore(nameStartsWith("org.eclipse.osgi"));
		
		// add advice to "methods"
		for ( MethodLocator method : this.getMethods() ) {
			//System.err.println( "INSTRUMENTING " + method.className() + " -> " + method.methodName() );
			logger.atWarning().log("INSTRUMENTING " + method.className() + " -> " + method.methodName() );
			try {

				// ignore methods listed as excludes in JOT rule
				for ( MethodLocator eloc : this.getExcludes() ) {
					//System.out.println ( "EXCLUDING: " + eloc.className() + " from " + method );
					logger.atInfo().log( "EXCLUDING: " + eloc.className() + " from " + method );
					builder.ignore(nameStartsWith(eloc.className()) );
					builder.ignore(hasGenericSuperType(failSafe(named(eloc.className()))));
				}
				
				// transform constructors with JOT exception rule (CE)
				if ( method.isConstructor() && hasException() ) {
					builder = builder
					.type(hasGenericSuperType(failSafe(named(method.className()))))
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(CEAdvice.class)
							.on( isConstructor())) );
				}

				// transform constructors with no JOT exception rule (CNE)
				else if ( method.isConstructor() ) {
					builder = builder
					.type(hasGenericSuperType(failSafe(named(method.className()))))
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(CNEAdvice.class)
							.on( isConstructor())) );
				}
				
				// transform methods with a return but no JOT exception (MR)
				else if ( hasReturn() ) {
					builder = builder
					.type(hasGenericSuperType(failSafe(named(method.className()))))
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(MRAdvice.class)
							.on(named(method.methodName())) ) );
				}
				
				// transform methods with no return and JOT exception rule (MVE)
				else if ( hasException() ) {
					builder = builder
					.type(hasGenericSuperType(failSafe(named(method.className()))))
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(MVEAdvice.class)
							.on(named(method.methodName())) ) );
				}
				
				// transform methods with no return and no JOT exception (MVNE)
				else {
					builder = builder
					.type(hasGenericSuperType(failSafe(named(method.className()))))
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(MVNEAdvice.class)
							.on(named(method.methodName())) ) );
				}
				
			} catch (Exception e) {
				//System.err.println("WARNING: Error instrumenting: " + e.getMessage());
				logger.atWarning().log("WARNING: Error instrumenting: " + e.getMessage());
				//e.printStackTrace();
				logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
			}
		}
				
		// add advice to "scopes"
		for ( MethodLocator scope : this.getScopes() ) {
			//System.err.println( "SCOPERIZING " + scope.className() + " -> " + scope.methodName() );
			logger.atWarning().log("SCOPERIZING " + scope.className() + " -> " + scope.methodName() );
			try {				
				// constructors can't use Advice with onThrowable, so they get an ASM wrapper
				// that scopes the constructor body (see ScopeCtorWrapper)
				if ( scope.isConstructor() ) {
					builder = builder
					.type(hasGenericSuperType(failSafe(named(scope.className()))))
					.transform((b, td, cl, m, pd) -> b.visit( new AsmVisitorWrapper.ForDeclaredMethods()
						.constructor(isConstructor(), new ScopeCtorWrapper(this.getIndex(), scope.getIndex()))));
				}
				else {
					builder = builder
					.type(hasGenericSuperType(failSafe(named(scope.className()))))
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, scope.getIndex() )
						.to(ScopeAdvice.class)
						.on(named(scope.methodName()).and(not(isConstructor()))) ) );
				}
			
			} catch (Exception e) {
				//System.err.println("WARNING: Error instrumenting: " + e.getMessage());
				logger.atWarning().log("WARNING: Error instrumenting: " + e.getMessage());
				//e.printStackTrace();
				logger.atWarning().log( ExceptionUtils.getStackTrace(e) );
			}
		}

		return builder;
	}	
	
}
