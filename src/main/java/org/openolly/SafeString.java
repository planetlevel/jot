package org.openolly;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Vector;

import com.google.common.flogger.FluentLogger;

public class SafeString {
	
	private static final FluentLogger logger = FluentLogger.forEnclosingClass();
	
	public static void main( String[] args ) {
		Object[] arr = {"foo","bar",new String[]{"blue","red"}};
		//System.out.println( "CT: " + arr.getClass().getComponentType() );
		logger.atInfo().log( "CT: " + arr.getClass().getComponentType() );
		//System.out.println( "ASS: " + arr.getClass().getComponentType().isPrimitive());
		logger.atInfo().log("ASS: " + arr.getClass().getComponentType().isPrimitive());
		//System.out.println( "A: " + SafeString.format(arr, false));
		logger.atInfo().log("A: " + SafeString.format(arr, false));
		int[] arr1 = {1,2};
		//System.out.println( "CT: " + arr1.getClass().getComponentType() );
		logger.atInfo().log("CT: " + arr1.getClass().getComponentType() );
		//System.out.println( "ASS: " + arr1.getClass().getComponentType().isPrimitive());
		logger.atInfo().log("ASS: " + arr1.getClass().getComponentType().isPrimitive());
		//System.out.println( "A: " + SafeString.format(arr1, false));
		logger.atInfo().log("A: " + SafeString.format(arr1, false));
		Vector<Integer> v = new Vector();
		v.add( 1 );
		v.add( 2);
		//System.out.println( "V: " + SafeString.format(v.elements(), false));
		logger.atInfo().log( "V: " + SafeString.format(v.elements(), false));
		Object[] arr3 = {"foo","bar",null};
		//System.out.println( "A3: " + SafeString.format(arr3, false));
		logger.atInfo().log(  "A3: " + SafeString.format(arr3, false));
		Object[] arr4 = null;
		//System.out.println( "A4: " + SafeString.format(arr4, false));
		logger.atInfo().log( "A4: " + SafeString.format(arr4, false));
	}
	public static String format( Object o, boolean debug ) {
		return format( o, false, debug );
	}
	
	// convert enumeration to list before sending
	public static String format( Object o, boolean readOnly, boolean debug ) {
		if ( o == null ) {
			return "null";
		}
		if ( o instanceof String ) {
			return (String)o;
		}
		if ( o instanceof Entry ) {
			return formatMapEntry( (Entry)o );
		}
		if ( !readOnly && o instanceof Enumeration ) {
			return formatEnumeration( (Enumeration)o );
		}
		if ( o.getClass().isArray() ) {
			return( formatArray( o ) );
		}
		if ( o instanceof Collection ) {
			return Arrays.deepToString(((Collection)o).toArray());
		}
		if ( o instanceof Map ) {
			return formatMap( (Map)o );
		}
		String ret = "{" + o.getClass() + ":" + o.toString() + "}";
		if ( debug ) {
			//System.out.println( "[SENSOR] Defaulting to toString() - " + ret );
			logger.atFinest().log( "[SENSOR] Defaulting to toString() - " + ret );
			dumpMethods(o);
		}
		return ret;
	}

	private static void dumpMethods(Object o) {
		//System.err.println( "[SENSOR] Possible methods to invoke on: " + o.getClass());
		logger.atWarning().log("[SENSOR] Possible methods to invoke on: " + o.getClass());
		for ( Method m : getAllMethodsInHierarchy(o.getClass())) {
			if ( m.getParameterCount() == 0 ) {
				//System.err.println( "  " + m.getName() + "()" );
				logger.atWarning().log("  " + m.getName() + "()" );
			}
		}
	}

	public static Method[] getAllMethodsInHierarchy(Class<?> objectClass) {
        Set<Method> allMethods = new HashSet<Method>();
        Method[] declaredMethods = objectClass.getDeclaredMethods();
        Method[] methods = objectClass.getMethods();
        if (objectClass.getSuperclass() != null) {
            Class<?> superClass = objectClass.getSuperclass();
            Method[] superClassMethods = getAllMethodsInHierarchy(superClass);
            allMethods.addAll(Arrays.asList(superClassMethods));
        }
        allMethods.addAll(Arrays.asList(declaredMethods));
        allMethods.addAll(Arrays.asList(methods));
        return allMethods.toArray(new Method[allMethods.size()]);
    }
	
	private static String formatArray( Object o ) {
		if ( !o.getClass().isArray() ) return "{not an array}";
		Class type = o.getClass().getComponentType();
		if ( !type.isPrimitive() ) return Arrays.deepToString( (Object[])o );
		if ( type == byte.class ) return Arrays.toString( (int[])o );
		if ( type == short.class ) return Arrays.toString( (int[])o );
		if ( type == int.class ) return Arrays.toString( (int[])o );
		if ( type == long.class ) return Arrays.toString( (int[])o );
		if ( type == float.class ) return Arrays.toString( (int[])o );
		if ( type == double.class ) return Arrays.toString( (int[])o );
		if ( type == boolean.class ) return Arrays.toString( (int[])o );
		if ( type == char.class ) return Arrays.toString( (int[])o );
		return "{unknown}";
	}
	
	private static String formatMapEntry(Entry o) {
		StringBuilder sb = new StringBuilder("[");
		sb.append( o.getKey() );
		sb.append( "=" );
		sb.append( o.getValue() );
		sb.append( "]");
		return sb.toString();
	}

	// FIXME: danger, this burns the enumeration, don't modify an enumeration being returned!
	private static String formatEnumeration(Enumeration o) {
		List list = Collections.list(o);
		return list.toString();
	}

	private static String formatMap(Map o) {
		StringBuilder sb = new StringBuilder("[");
		for ( Entry e : (Set<Map.Entry>)o.entrySet() ) {
			sb.append( format( e, false ) );
			sb.append( "," );
		}
		sb.setLength(sb.length()-1);
		return sb.toString() + "]";
	}

}
