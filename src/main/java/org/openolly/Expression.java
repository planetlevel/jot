package org.openolly;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import org.apache.commons.lang3.StringUtils;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import com.google.common.flogger.FluentLogger;

public class Expression {

	private static final FluentLogger logger = FluentLogger.forEnclosingClass();

	private static ExpressionParser parser = new SpelExpressionParser();
	private org.springframework.expression.Expression exp = null;

	private StandardEvaluationContext context = new StandardEvaluationContext();
	
	public Expression(String expression) throws ParseException, NoSuchMethodException, SecurityException {
		exp = parser.parseExpression(expression);
		context.registerFunction("toUpper", StringUtils.class.getMethod("upperCase", String.class));
		context.registerFunction("toLower", StringUtils.class.getMethod("upperCase", String.class));
		context.registerFunction("sort", Collections.class.getMethod("sort", List.class));
	}

	public Object execute(Object obj, Object[] params, Object ret, String caller, StackTraceElement[] stack) {
		
		// convert input if necessary
		obj = convert( obj );
		params = convert( params );
		ret = convert( ret );
		
		context.setVariable("OBJ", obj);
		context.setVariable("ARGS", params);
		context.setVariable("RET", ret);
		if (params != null) {
			for (int i = 0; i < params.length; i++) {
				context.setVariable("P" + i, params[i]);
			}
		}
		context.setVariable("CALLER", caller);
		context.setVariable("STACK", stack);
		
		// convert output if necessary
		Object result = null;
		try { 
			result = convert( exp.getValue(context) );
		} catch( Exception e ) {
			logger.atWarning().log( "[JOT] Couldn't evaluate %s: %s", this, e.getMessage() );
			result = null;
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
