package org.openolly;

import static net.bytebuddy.matcher.ElementMatchers.failSafe;
import static net.bytebuddy.matcher.ElementMatchers.hasGenericSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.nameContains;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.declaresMethod;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isDeclaredBy;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;

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
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

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
	private String blockWhen = null;        // makes this a rule, true for every call or an expression that says when. block-when in the .jot file
	private Expression blockCondition = null;   // blockWhen as an expression, null when it is true for every call
	private boolean blockNever = false;
	private boolean appScope = true;        // with no scopes of its own, this applies only while the application is running, see AppScope     // a condition that couldn't be read never blocks, a mistake must not block everything
	private boolean debug = false;
	// false stops this rule from protecting, so it only reports. Null leaves it to jot.protect
	private Boolean protect = null;

	// -Djot.protect=false makes every rule only report, nothing is stopped
	private static volatile boolean protectAll = !"false".equalsIgnoreCase( System.getProperty( "jot.protect" ) );

	// what the control file says, see ControlFile. The master switch, and this rule's own setting if it has one
	private static volatile boolean controlMaster = true;
	private volatile Boolean controlProtect = null;
	// false switches this sensor or rule off, so it does nothing at all. Null leaves it on
	private Boolean enabled = null;
	// what the control file says about enabled, which wins over the .jot file. Null leaves it to the .jot file
	private volatile Boolean controlEnabled = null;
	private boolean hasReturn = false;

	private Pattern namePattern = Pattern.compile( "[a-z][a-z0-9]*(\\-[a-z0-9]+)*");
	private Pattern descriptionPattern = Pattern.compile( "^.*$");
	private Pattern methodPattern = Pattern.compile( "^(!)?([\\p{L}_$][\\p{L}\\p{N}_$]*\\.)*(<init>|[\\p{L}_$][\\p{L}\\p{N}_$]*)$");
	private Pattern annotationPattern = Pattern.compile( "^@([\\p{L}_$][\\p{L}\\p{N}_$]*\\.)*[\\p{L}_$][\\p{L}\\p{N}_$]*$");
	private Pattern capturePattern = Pattern.compile( "^.*$");

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
	/**
	 * A sensor that observes leaves out what the platform did while loading classes or compiling pages, see PlatformWork.
	 * A rule doesn't call this, it reports and blocks whatever it sees.
	 */
	private void publishObserved(Event event) {
		if ( isRule() ) return;
		if ( PlatformWork.inside( event.getStack() ) ) return;
		EventBus.publish( event );
	}

	/**
	 * Walking the stack is expensive, so it is only done once we know the sensor will really run,
	 * not for every call to a method that happens to have a sensor on it.
	 */
	private static final String AGENT_JAR = agentJar();

	private static String agentJar() {
		try {
			// a class on the boot class path has no code source, but its resource URL still names the jar
			java.net.URL url = Sensor.class.getResource( "Sensor.class" );
			if ( url == null || !"jar".equals( url.getProtocol() ) ) return null;
			String spec = url.getPath();
			return new java.io.File( new java.net.URI( spec.substring( 0, spec.indexOf( "!/" ) ) ) ).getPath();
		} catch ( Exception e ) {
			return null;
		}
	}

	/** The JVM opens JOT's own jar to load the agent, which says nothing about the application. */
	static boolean isAgentJar(String path) {
		return AGENT_JAR != null && AGENT_JAR.equals( path );
	}

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
		return execute( advice, caller, obj, params, ret, stack, null );
	}

	/**
	 * The attributes of the annotation that selected the method at methodIndex, for a method written as
	 * @the.Annotation. Null for any other method, which is the usual case, so this is cheap.
	 */
	public java.util.Map<String, Object> annotationFor(int methodIndex, Class<?> type, String name, String descriptor) {
		MethodLocator loc = methods.get( methodIndex );
		return loc.isAnnotation() ? loc.annotationValues( type, name, descriptor ) : null;
	}

	public List<Object> execute(String advice, String caller, Object obj, Object[] params, Object ret, StackTraceElement[] stack,
			java.util.Map<String, Object> annotation) {

		// no sensor fires while JOT's own code is running, in this sensor or any other
		if ( JotScope.active() ) return new ArrayList<Object>();

		// a sensor that is not enabled records nothing, and a rule that is not enabled neither stops a call nor reports one
		if ( !isEnabled() ) return new ArrayList<Object>();

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
			// no scopes of its own means the application is its scope, and nothing outside it counts
			else if ( appScope && AppScope.configured() && !AppScope.active() ) return results;
	
			if ( stack == null && ( !captures.isEmpty() || isRule() ) ) stack = currentStack();

			for (Expression capture : captures) {
				try {
					Object o = capture.execute(obj, params, ret, caller, stack, annotation);
					
					if ( o instanceof Collection ) {
						for ( Object item : (Collection)o ) {
							String safe = SafeString.format( item, debug );
							boolean matched = !isAgentJar( safe ) && Matcher.eval( safe, getPositiveMatchers(), getNegativeMatchers() );
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
						boolean matched = !isAgentJar( safe ) && Matcher.eval( safe, getPositiveMatchers(), getNegativeMatchers() );
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

			// if there are either results or zero captures, block, or report, if this is a rule
			if ( isRule() ) {
				if ( ( captures.isEmpty() || !results.isEmpty() ) && blockHolds( obj, params, ret, caller, stack, annotation ) ) {
					String details = results.stream().map( String::valueOf ).collect( Collectors.joining( " | " ) );
					if ( isProtected() ) {
						SensorException e = new SensorException( getRuleMessage() );
						EventBus.publish( new Event( getName() + "-blocked", details, stack, Event.Action.BLOCKED, getRuleMessage() ) );
						throw e;
					}
					// not protecting, so say what would have been stopped and let the call go ahead
					EventBus.publish( new Event( getName() + "-monitored", details, stack, Event.Action.MONITORED, getRuleMessage() ) );
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
		boolean annotation = value.startsWith( "@" );
		Pattern pattern = annotation ? annotationPattern : methodPattern;
		if (!pattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed method (" + value + ") must match " + pattern.pattern() + ". Continuing", this );
		}
		addMethod( value );
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
		if ( value.startsWith( "@" ) ) {
			logger.atWarning().log( "[JOT %s] YAML error: a scope can't be an annotation (" + value + "), use it in methods. Ignoring", this );
			return this;
		}
		if (!methodPattern.matcher(value).matches()) {
			logger.atWarning().log( "[JOT %s] YAML error: malformed scope (" + value + ") must match " + methodPattern.pattern(), this );
		}
		addScope( value, negative );
		appScope = false;
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

	/** No list leaves the application as the scope. A list, even an empty one, is the JOT's own, and empty means anywhere. */
	public Sensor scopes( List<String> list ) {
		if ( list == null ) {
			return this;
		}
		appScope = false;
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

	/**
	 * Makes this a rule. true blocks every call that gets this far, anything else is a boolean expression over the same
	 * variables as a capture, like #P0 < 2048, and the call is only stopped when it is true. Whether the rule really
	 * stops the call or only reports it is up to the mode, see protectAll and protect. The message is the description,
	 * then the condition.
	 */
	public Sensor blockWhen(String value) {
		if ( value == null || value.trim().isEmpty() ) {
			return this;
		}
		blockWhen = value.trim();
		blockCondition = null;
		blockNever = false;
		if ( blockWhen.equalsIgnoreCase( "true" ) ) {
			return this;
		}
		try {
			blockCondition = new Expression( blockWhen );
		} catch ( Exception e ) {
			logger.atWarning().log( "[JOT %s] YAML error: block-when (%s) is not an expression, so this rule will never block. %s", this, blockWhen, e.getMessage() );
			blockNever = true;
		}
		return this;
	}

	/** True if the condition holds for this call. An expression that fails counts as false, the application keeps running. */
	private boolean blockHolds(Object obj, Object[] params, Object ret, String caller, StackTraceElement[] stack,
			java.util.Map<String, Object> annotation) {
		if ( blockNever ) return false;
		if ( blockCondition == null ) return true;
		Object o = blockCondition.execute( obj, params, ret, caller, stack, annotation );
		return Boolean.TRUE.equals( o ) || ( o instanceof String && "true".equalsIgnoreCase( ( (String) o ).trim() ) );
	}

	public Sensor debug( boolean value ) {
		debug = value;
		return this;
	}

	/**
	 * Setting this to false makes the rule report violations without stopping them. A rule can only turn its
	 * own protection off. It can't turn it on when jot.protect is false, which switches off every rule.
	 */
	public Sensor protect( Boolean value ) {
		protect = value;
		return this;
	}

	/**
	 * True if a violation of this rule stops the call. Either master switch being off turns every rule off,
	 * and the control file can't turn on what -Djot.protect=false turned off. Otherwise the control file's
	 * setting for this rule wins over the .jot file's, so a rule written with protect: false can be switched
	 * on while the application runs.
	 */
	public boolean isProtected() {
		if ( !protectAll || !controlMaster ) return false;
		if ( controlProtect != null ) return controlProtect;
		return !Boolean.FALSE.equals( protect );
	}

	/** Written as enabled: false in the .jot file, this switches the sensor or rule off. Null leaves it on. */
	public Sensor enabled( Boolean value ) {
		enabled = value;
		return this;
	}

	/**
	 * True if this sensor or rule runs. The control file's setting wins over the .jot file's, so one written with
	 * enabled: false can be switched on while the application runs, and one that is on can be switched off.
	 */
	public boolean isEnabled() {
		if ( controlEnabled != null ) return controlEnabled;
		return !Boolean.FALSE.equals( enabled );
	}

	/**
	 * Applies settings from the control file. protect is whether each rule blocks and enabled is whether each sensor
	 * or rule runs. One that isn't in its map goes back to its .jot setting, and names that match no sensor are ignored.
	 */
	public static void applyControl(boolean master, java.util.Map<String, Boolean> protect, java.util.Map<String, Boolean> enabled) {
		controlMaster = master;
		for ( Sensor s : sensors ) {
			s.controlProtect = protect.get( s.getName() );
			s.controlEnabled = enabled.get( s.getName() );
		}
	}

	public static void applyControl(boolean master, java.util.Map<String, Boolean> protect) {
		applyControl( master, protect, java.util.Map.of() );
	}

	/** Whether the control file's master switch has protection on. */
	public static boolean isControlMasterOn() {
		return controlMaster;
	}

	/** True if the JVM was started with -Djot.protect=false, which locks every rule to report only. */
	public static boolean isLockedToMonitor() {
		return !protectAll;
	}

	/** Set whether rules protect at all, the same as -Djot.protect. */
	public static void protectAll( boolean value ) {
		protectAll = value;
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
	
	/** The message of a rule, or null for a sensor. It is the description, then the condition if there is one. */
	public String getRuleMessage() {
		if ( blockWhen == null ) return null;
		String what = description != null ? description : ( name != null ? name : "JOT rule" );
		return blockCondition == null && !blockNever ? what : what + ": " + blockWhen;
	}

	public String getBlockWhen() {
		return blockWhen;
	}

	/** A rule has a block-when, a sensor without one only observes. */
	public boolean isRule() {
		return blockWhen != null;
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
		if ( !scopeReported.get() && name != null && isEnabled() && !JotScope.active() && scopeReported.compareAndSet( false, true ) ) {
			publishActive( loc );
		}
	}

	// whether this JOT has said that its scope is active, which it does once and never again until the JVM is started again
	private final java.util.concurrent.atomic.AtomicBoolean scopeReported = new java.util.concurrent.atomic.AtomicBoolean( false );

	/**
	 * A JOT with scopes says when one of them is first entered, with an observed event named for the JOT plus "-active", and
	 * the scope method as what it saw. That is all, once for each JOT in the life of the JVM. It is how to tell that the
	 * code a rule watches, like the vulnerable code of a CVE, is really running in an application. What happens inside the
	 * scope is reported by the JOT as usual.
	 */
	private void publishActive(MethodLocator scope) {
		JotScope.enter();
		try {
			EventBus.publish( new Event( getName() + "-active", scope.className() + "." + scope.methodName(), currentStack() ) );
		} finally {
			JotScope.exit();
		}
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
	

	/** By class, which includes its subtypes, or for @the.Annotation the classes that carry it or have a method that does. */
	static ElementMatcher<TypeDescription> typeMatcher(MethodLocator method) {
		if ( !method.isAnnotation() ) return hasGenericSuperType(failSafe(named(method.className())));
		ElementMatcher<TypeDescription> marked = named(method.annotationName());
		ElementMatcher.Junction<TypeDescription> typeCarries = ElementMatchers.<TypeDescription>isAnnotatedWith(marked);
		return failSafe(typeCarries.or(declaresMethod(ElementMatchers.<MethodDescription>isAnnotatedWith(marked))));
	}

	/** By method name, or for @the.Annotation the methods that carry it and the methods of a class that does. */
	static ElementMatcher<MethodDescription> methodMatcher(MethodLocator method) {
		if ( !method.isAnnotation() ) return named(method.methodName());
		ElementMatcher<TypeDescription> marked = named(method.annotationName());
		ElementMatcher.Junction<TypeDescription> typeCarries = ElementMatchers.<TypeDescription>isAnnotatedWith(marked);
		return failSafe(isMethod().and(not(isAbstract()))
			.and(ElementMatchers.<MethodDescription>isAnnotatedWith(marked).or(isDeclaredBy(typeCarries))));
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

				final ElementMatcher<TypeDescription> typeMatcher = typeMatcher( method );
				final ElementMatcher<MethodDescription> methodMatcher = methodMatcher( method );

				// ignore methods listed as excludes in JOT rule
				for ( MethodLocator eloc : this.getExcludes() ) {
					//System.out.println ( "EXCLUDING: " + eloc.className() + " from " + method );
					logger.atInfo().log( "EXCLUDING: " + eloc.className() + " from " + method );
					builder.ignore(nameStartsWith(eloc.className()) );
					builder.ignore(hasGenericSuperType(failSafe(named(eloc.className()))));
				}
				
				// transform constructors that are rules (CE)
				if ( method.isConstructor() && isRule() ) {
					builder = builder
					.type(typeMatcher)
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(CEAdvice.class)
							.on( isConstructor())) );
				}

				// transform constructors that are not rules (CNE)
				else if ( method.isConstructor() ) {
					builder = builder
					.type(typeMatcher)
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(CNEAdvice.class)
							.on( isConstructor())) );
				}
				
				// transform methods with a return that are not rules (MR)
				else if ( hasReturn() ) {
					builder = builder
					.type(typeMatcher)
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(MRAdvice.class)
							.on(methodMatcher) ) );
				}
				
				// transform methods with no return that are rules (MVE)
				else if ( isRule() ) {
					builder = builder
					.type(typeMatcher)
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(MVEAdvice.class)
							.on(methodMatcher) ) );
				}
				
				// transform methods with no return that are not rules (MVNE)
				else {
					builder = builder
					.type(typeMatcher)
					.transform((b, td, cl, m, pd) -> b.visit( Advice
						.withCustomMapping()
						.bind(SensorIndexValue.class, this.getIndex() )
						.bind(MethodIndexValue.class, method.getIndex() )
						.to(MVNEAdvice.class)
							.on(methodMatcher) ) );
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
