package org.openolly;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import org.openolly.log.FluentLogger;

public class Expression {

	private static final FluentLogger logger = FluentLogger.forEnclosingClass();

	private static ExpressionParser parser = new SpelExpressionParser();
	private org.springframework.expression.Expression exp = null;

	/**
	 * The variables of a call are set on a context before the expression reads them, so a context shared by threads would
	 * hand one request's #P0 to another that is running at the same time. Each thread has its own. It is one for the thread and
	 * not one for each expression, since they are all set up the same, and a thread only runs one expression at a time because no
	 * sensor fires inside JOT's own code. That keeps it to about a kilobyte for each thread, not for each thread and sensor.
	 */
	private static final ThreadLocal<StandardEvaluationContext> contexts = new ThreadLocal<StandardEvaluationContext>();
	/** how many P variables each thread's context has been given, so a call with fewer arguments doesn't see the last call's */
	private static final ThreadLocal<int[]> parameterCounts = ThreadLocal.withInitial( () -> new int[1] );

	public Expression(String expression) throws ParseException, NoSuchMethodException, SecurityException {
		exp = parser.parseExpression(expression);
		// checked once here, so a function that can't be registered is a mistake in the expression when it is written
		newContext();
	}

	private StandardEvaluationContext context() {
		StandardEvaluationContext context = contexts.get();
		if ( context == null ) {
			try {
				context = newContext();
			} catch ( NoSuchMethodException e ) {
				throw new IllegalStateException( e );
			}
			contexts.set( context );
		}
		return context;
	}

	private static StandardEvaluationContext newContext() throws NoSuchMethodException {
		StandardEvaluationContext context = new StandardEvaluationContext();
		context.registerFunction("toUpper", StringUtils.class.getMethod("upperCase", String.class));
		context.registerFunction("toLower", StringUtils.class.getMethod("upperCase", String.class));
		// so a map can be read as #ANNOTATION.roles as well as #ANNOTATION['roles']
		context.addPropertyAccessor(new org.springframework.expression.PropertyAccessor() {
			public Class<?>[] getSpecificTargetClasses() { return new Class<?>[] { java.util.Map.class }; }
			public boolean canRead(org.springframework.expression.EvaluationContext c, Object target, String name) {
				return target instanceof java.util.Map && ((java.util.Map<?, ?>) target).containsKey(name);
			}
			public org.springframework.expression.TypedValue read(org.springframework.expression.EvaluationContext c, Object target, String name) {
				return new org.springframework.expression.TypedValue(((java.util.Map<?, ?>) target).get(name));
			}
			public boolean canWrite(org.springframework.expression.EvaluationContext c, Object target, String name) { return false; }
			public void write(org.springframework.expression.EvaluationContext c, Object target, String name, Object value) { }
		});
		context.registerFunction("sort", Collections.class.getMethod("sort", List.class));
		return context;
	}

	public Object execute(Object obj, Object[] params, Object ret, String caller, StackTraceElement[] stack) {
		return execute( obj, params, ret, caller, stack, null );
	}

	/** annotation is the attributes of the annotation a method was selected by, available as #ANNOTATION. */
	public Object execute(Object obj, Object[] params, Object ret, String caller, StackTraceElement[] stack,
			java.util.Map<String, Object> annotation) {
		
		// convert input if necessary
		obj = convert( obj );
		params = convert( params );
		ret = convert( ret );
		
		StandardEvaluationContext context = context();
		int[] known = parameterCounts.get();
		int count = params == null ? 0 : params.length;
		context.setVariable("OBJ", obj);
		context.setVariable("ARGS", params);
		context.setVariable("RET", ret);
		for (int i = 0; i < Math.max( count, known[0] ); i++) {
			context.setVariable("P" + i, i < count ? params[i] : null);
		}
		known[0] = Math.max( count, known[0] );
		context.setVariable("CALLER", caller);
		context.setVariable("STACK", stack);
		context.setVariable("ANNOTATION", annotation);
		
		// convert output if necessary
		Object result = null;
		try { 
			result = convert( exp.getValue(context) );
		} catch( Exception e ) {
			logger.atWarning().log( "[JOT] Couldn't evaluate %s: %s", this, e.getMessage() );
			result = null;
		} finally {
			// the context stays with the thread, and must not keep the request's objects alive until the next call
			context.setVariable("OBJ", null);
			context.setVariable("ARGS", null);
			context.setVariable("RET", null);
			for (int i = 0; i < known[0]; i++) context.setVariable("P" + i, null);
			context.setVariable("STACK", null);
			context.setVariable("ANNOTATION", null);
		}
		return result;
	}

	public Object[] convert( Object[] o ) {
		if ( o != null ) {
			for ( int i = 0; i < o.length; i++ ) {
				o[i] = convert( o[i] );
			}
		}
		return o;
	}
	
	// FIXME: this is where any conversions on expression output should happen
	public Object convert(Object o) {
		if ( o != null ) {
			// note: this burns the enumeration, use only if no side-effect
			if ( Enumeration.class.isAssignableFrom( o.getClass() ) ) {
				o = Collections.list((Enumeration)o);
			}
		}
		return o;
	}

	public String toString() {
		return exp.getExpressionString();
	}
}
