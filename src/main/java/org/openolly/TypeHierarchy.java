package org.openolly;

import java.security.ProtectionDomain;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDefinition;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.utility.JavaModule;

/**
 * Which classes are, or extend or implement, a given class, answered from a cache shared by every sensor. Each sensor has its
 * own transformer, so that it can go on and off while the application runs, and each transformer asks about every class that
 * loads. Without this each of them walked the class's whole hierarchy and read each class file on the way, which with a
 * few hundred matchers made loading a few hundred classes take minutes. Here a class's supertypes are worked out once for a
 * class loader, and a matcher is only a scan of a short array. The names are interned, so each class name is held once however many
 * classes have it above them, and the arrays are compared by identity. That keeps the cache to about a hundred bytes a class.
 */
final class TypeHierarchy {

	private static final Object BOOT = new Object();
	private static final Map<Object, Map<String, String[]>> loaders = Collections.synchronizedMap(new WeakHashMap<Object, Map<String, String[]>>());

	private TypeHierarchy() {
	}

	/** Matches a class that is one of the names or extends or implements one of them, as hasGenericSuperType does. */
	static AgentBuilder.RawMatcher extending(String... given) {
		final String[] names = new String[given.length];
		for ( int i = 0; i < given.length; i++ ) names[i] = given[i].intern();
		return new AgentBuilder.RawMatcher() {
			@Override
			public boolean matches(TypeDescription type, ClassLoader loader, JavaModule module, Class<?> redefined, ProtectionDomain domain) {
				try {
					for ( String above : supertypes( type, loader ) ) {
						for ( String name : names ) {
							if ( above == name ) return true;
						}
					}
				} catch ( Throwable e ) {
					// a class whose hierarchy can't be read doesn't match, which is what failSafe did
				}
				return false;
			}
		};
	}

	/** The names of the type and every class and interface above it. */
	static String[] supertypes(TypeDescription type, ClassLoader loader) {
		Object key = loader == null ? BOOT : loader;
		Map<String, String[]> names = loaders.get( key );
		if ( names == null ) {
			synchronized ( loaders ) {
				names = loaders.get( key );
				if ( names == null ) {
					names = new ConcurrentHashMap<String, String[]>();
					loaders.put( key, names );
				}
			}
		}
		return of( type, names );
	}

	private static String[] of(TypeDefinition type, Map<String, String[]> names) {
		String name = type.asErasure().getName().intern();
		String[] known = names.get( name );
		if ( known != null ) return known;
		Set<String> all = new LinkedHashSet<String>();
		all.add( name );
		try {
			TypeDefinition parent = type.getSuperClass();
			if ( parent != null ) Collections.addAll( all, of( parent, names ) );
			for ( TypeDefinition face : type.getInterfaces() ) Collections.addAll( all, of( face, names ) );
		} catch ( Throwable e ) {
			// a supertype whose class file can't be read now ends the walk there, and what was found is not kept, since it may be readable later
			return all.toArray( new String[0] );
		}
		String[] found = all.toArray( new String[0] );
		names.put( name, found );
		return found;
	}

	/** For tests, forgets every class. */
	static void clear() {
		loaders.clear();
	}
}
