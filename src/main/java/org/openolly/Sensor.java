package org.openolly;

import static net.bytebuddy.matcher.ElementMatchers.failSafe;
import static net.bytebuddy.matcher.ElementMatchers.hasGenericSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.nameContains;
import static net.bytebuddy.matcher.ElementMatchers.named;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.openolly.advice.CEAdvice;
import org.openolly.advice.CNEAdvice;
import org.openolly.advice.MRAdvice;
import org.openolly.advice.MVEAdvice;
import org.openolly.advice.MVNEAdvice;
import org.openolly.advice.ScopeAdvice;
import org.openolly.advice.SensorException;
import org.openolly.advice.scope.BinaryScope;
import org.openolly.reporting.Event;
import org.openolly.reporting.Trace;

import com.google.common.flogger.FluentLogger;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

public class Sensor {

	private static final FluentLogger logger = FluentLogger.forEnclosingClass();
	private static List<Sensor> sensors = new ArrayList<Sensor>();

	// protect against ANY sensor firing inside ANY other sensor
	// a threadlocal scope for *this* sensor for *this* thread
	private BinaryScope globalScope = new BinaryScope();

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
	private boolean hasReturn = false;

	private Pattern namePattern = Pattern.compile( "([a-z]+\\-)*[a-z]+");
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
			if ( s.getName().equals( name ) ) {
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

	public List<Object> execute(String advice, String caller, Object obj, Object[] params, Object ret, StackTraceElement[] stack) {			

		// protect against calling execute from itself
		if ( globalScope.inScope() ) {
			
			// FIXME: add if ( debug ) before all logger calls? Or figure out how to do it right
			logger.atWarning().log( "[JOT %s] Skipping sensor - already in scope %s", this, globalScope.value() );
			return new ArrayList<Object>();
		}

		// return results for making tests easier
		List<Object> results = new ArrayList<Object>();
		try {
			globalScope.enterScope();
			
			// if there are scopes, and none are in scope, quit
			if ( !scopes.isEmpty() ) {
				boolean inScope = false;
				for ( MethodLocator scope : scopes ) {
					inScope |= ( scope.inScope() );
				}
				if ( !inScope ) return results;
			}
	
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
								Trace.getCurrentTrace().addEvent( event );
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
							Trace.getCurrentTrace().addEvent( event );
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
					String details = SafeString.format( results, false );
					SensorException e = new SensorException( getException() );
					logger.atInfo().log( "[JOT %s] %s: %s", this, getException(), details );
					throw e;
				}
			}			
		} finally {
			globalScope.leaveScope();
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
		MethodLocator loc = new MethodLocator( value );
		methods.add( loc );
		loc.setIndex( methods.indexOf( loc ) );
		return this;
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
		scopes.add(new MethodLocator(value, negative));
		return this;
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
	
//=========== stop reentry into sensors

	public void enterGlobalScope() {
		globalScope.enterScope();
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
					.transform((b, td, cl, m) -> b.visit( Advice
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
					.transform((b, td, cl, m) -> b.visit( Advice
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
					.transform((b, td, cl, m) -> b.visit( Advice
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
					.transform((b, td, cl, m) -> b.visit( Advice
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
					.transform((b, td, cl, m) -> b.visit( Advice
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
				builder = builder
				.type(hasGenericSuperType(failSafe(named(scope.className()))))
				.transform((b, td, cl, m) -> b.visit( Advice
					.withCustomMapping()
					.bind(SensorIndexValue.class, this.getIndex() )
					.bind(MethodIndexValue.class, scope.getIndex() )
					.to(ScopeAdvice.class)
					.on(named(scope.methodName())
						.or(named(scope.methodName())
						.or(isConstructor()))) ) );
			
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
