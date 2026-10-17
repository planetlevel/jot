package org.openolly;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openolly.advice.scope.BinaryScope;

public class MethodLocator {
	public String clazz = null;
	public String method = null;
	public String params = null;
	public Method javaMethod = null;
	public boolean isVoid = false;
	private boolean negative = false;
	private int index = 0;

	private BinaryScope scope = new BinaryScope();

	// set for a locator written as @the.Annotation, which matches methods by what they are annotated with
	private String annotation = null;
	private final Map<String, Map<String, Object>> annotationCache = new ConcurrentHashMap<String, Map<String, Object>>();
	private static final Map<String, Object> NONE = Collections.<String, Object>emptyMap();

	public MethodLocator(String sig) {
		if ( sig.startsWith( "@" ) ) {
			annotation = sig.substring( 1 );
			clazz = sig;
			method = "*";
			return;
		}
		int idx = sig.lastIndexOf('.');
		if ( idx > -1 ) {
			clazz = sig.substring(0, idx);
			method = sig.substring(idx + 1);
		} else {
			clazz = sig;
		}
	}

	public MethodLocator( String clazz, String method) {
		this.clazz = clazz;
		this.method = method;
	}
	
	public MethodLocator(String sig, boolean negative ) {
		this( sig );
		this.negative = negative;
	}
	
	public void enterScope() {
		scope.enterScope();
	}
	
	public void leaveScope() {
		scope.leaveScope();
	}
	
	public boolean inScope() {
		if ( negative ) {
			return !scope.inScope();
		}
		return scope.inScope();
	}
	
	public boolean inOutermostScope() {
		if ( negative ) {
			return !scope.inOutermostScope();
		}
		return scope.inOutermostScope();
	}

	public int scopeValue() {
		return scope.value();
	}

	public Method getJavaMethod(Object o) throws NoSuchMethodException, SecurityException, ClassNotFoundException {
		if (javaMethod != null)
			return javaMethod;
		else {
			javaMethod = o.getClass().getMethod(method, null);
		}
		return javaMethod;
	}

	public String className() {
		return clazz;
	}

	public String methodName() {
		return method;
	}

	public boolean isAnnotation() {
		return annotation != null;
	}

	/** The annotation's class name for a locator written as @the.Annotation, otherwise null. */
	public String annotationName() {
		return annotation;
	}

	/**
	 * The attributes of the annotation on the method that is running, as name to value, or null if this isn't an
	 * annotation locator or the method has no such annotation. The method's own annotation wins, and if it has none
	 * the one on its class is used. Arrays come back as lists, classes as their names, enums as their names.
	 */
	public Map<String, Object> annotationValues(Class<?> type, String name, String descriptor) {
		if ( annotation == null || type == null ) return null;
		String key = type.getName() + "#" + System.identityHashCode( type.getClassLoader() ) + "." + name + descriptor;
		Map<String, Object> found = annotationCache.get( key );
		if ( found == null ) {
			try {
				found = lookup( type, name, descriptor );
			} catch ( Throwable t ) {
				found = NONE;
			}
			annotationCache.put( key, found );
		}
		return found == NONE ? null : found;
	}

	private Map<String, Object> lookup(Class<?> type, String name, String descriptor) {
		for ( Method m : type.getDeclaredMethods() ) {
			if ( m.getName().equals( name ) && descriptor( m ).equals( descriptor ) ) {
				Map<String, Object> values = valuesOf( m.getDeclaredAnnotations() );
				if ( values == null ) values = valuesOf( type.getDeclaredAnnotations() );
				return values == null ? NONE : values;
			}
		}
		return NONE;
	}

	private Map<String, Object> valuesOf(Annotation[] annotations) {
		for ( Annotation a : annotations ) {
			if ( a.annotationType().getName().equals( annotation ) ) return attributes( a );
		}
		return null;
	}

	static Map<String, Object> attributes(Annotation a) {
		Map<String, Object> values = new LinkedHashMap<String, Object>();
		for ( Method attribute : a.annotationType().getDeclaredMethods() ) {
			if ( attribute.getParameterCount() != 0 ) continue;
			try {
				attribute.setAccessible( true );
				values.put( attribute.getName(), plain( attribute.invoke( a ) ) );
			} catch ( Throwable t ) {
				// an attribute that can't be read is left out
			}
		}
		return values;
	}

	private static Object plain(Object value) {
		if ( value == null ) return null;
		if ( value instanceof Class ) return ((Class<?>) value).getName();
		if ( value instanceof Enum ) return ((Enum<?>) value).name();
		if ( value instanceof Annotation ) return attributes( (Annotation) value );
		if ( value.getClass().isArray() ) {
			List<Object> list = new ArrayList<Object>();
			for ( int i = 0; i < java.lang.reflect.Array.getLength( value ); i++ ) {
				list.add( plain( java.lang.reflect.Array.get( value, i ) ) );
			}
			return list;
		}
		return value;
	}

	/** The JVM descriptor of a method, like (Ljava/lang/String;I)V, which is what advice reports as #d. */
	static String descriptor(Method m) {
		StringBuilder sb = new StringBuilder( "(" );
		for ( Class<?> p : m.getParameterTypes() ) sb.append( descriptor( p ) );
		return sb.append( ")" ).append( descriptor( m.getReturnType() ) ).toString();
	}

	private static String descriptor(Class<?> c) {
		if ( c.isArray() ) return "[" + descriptor( c.getComponentType() );
		if ( !c.isPrimitive() ) return "L" + c.getName().replace( '.', '/' ) + ";";
		if ( c == void.class ) return "V";
		if ( c == int.class ) return "I";
		if ( c == long.class ) return "J";
		if ( c == boolean.class ) return "Z";
		if ( c == byte.class ) return "B";
		if ( c == char.class ) return "C";
		if ( c == short.class ) return "S";
		if ( c == float.class ) return "F";
		return "D";
	}

	public boolean isConstructor() {
		return method.equals( "<init>" );
	}
	
	public boolean isNegative() {
		return negative;
	}
	
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if ( clazz != null ) {
			sb.append( clazz + "." );
		}
		sb.append( method + "(" );
		if ( params != null ) {
			sb.append( params );
		}
		sb.append( ")" );
		return sb.toString();
	}

	public void setIndex(int index) {
		this.index = index;
	}
	public int getIndex() {
		return index;
	}

}
