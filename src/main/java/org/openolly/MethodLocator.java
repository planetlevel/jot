package org.openolly;

import java.lang.reflect.Method;

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

	public MethodLocator(String sig) {
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
