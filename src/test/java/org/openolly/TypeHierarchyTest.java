package org.openolly;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import net.bytebuddy.description.type.TypeDescription;

/** The cache of what a class extends, which every sensor's matcher reads. */
public class TypeHierarchyTest {

	@BeforeEach
	public void fresh() {
		TypeHierarchy.clear();
	}

	private boolean matches(Class<?> type, String... names) {
		ClassLoader loader = TypeHierarchyTest.class.getClassLoader();
		return TypeHierarchy.extending( names ).matches( TypeDescription.ForLoadedType.of( type ), loader, null, null, null );
	}

	@Test
	public void aClassMatchesItselfItsSuperclassesAndItsInterfaces() {
		Assertions.assertTrue( matches( ArrayList.class, "java.util.ArrayList" ) );
		Assertions.assertTrue( matches( ArrayList.class, "java.util.AbstractList" ) );
		Assertions.assertTrue( matches( ArrayList.class, "java.util.AbstractCollection" ) );
		Assertions.assertTrue( matches( ArrayList.class, "java.util.List" ) );
		Assertions.assertTrue( matches( ArrayList.class, "java.util.Collection" ) );   // two interfaces up
		Assertions.assertTrue( matches( ArrayList.class, "java.lang.Object" ) );
	}

	@Test
	public void aClassDoesNotMatchWhatItDoesNotExtend() {
		Assertions.assertFalse( matches( ArrayList.class, "java.util.Map" ) );
		Assertions.assertFalse( matches( ArrayList.class, "java.util.HashMap" ) );
		Assertions.assertFalse( matches( HashMap.class, "java.util.List" ) );
	}

	@Test
	public void anyOfSeveralNamesMatches() {
		Assertions.assertTrue( matches( HashMap.class, "java.util.List", "java.util.Map" ) );
		Assertions.assertFalse( matches( HashMap.class, "java.util.List", "java.util.Set" ) );
	}

	@Test
	public void theSupertypesAreTheSameWhenAskedAgain() {
		ClassLoader loader = TypeHierarchyTest.class.getClassLoader();
		TypeDescription type = TypeDescription.ForLoadedType.of( ArrayList.class );
		String[] first = TypeHierarchy.supertypes( type, loader );
		String[] second = TypeHierarchy.supertypes( type, loader );
		Assertions.assertSame( first, second, "the second answer comes from the cache" );
		Assertions.assertTrue( Arrays.asList( first ).contains( "java.util.RandomAccess" ) );
	}

	@Test
	public void theBootLoaderAndAnotherLoaderAreKeptApart() {
		TypeDescription type = TypeDescription.ForLoadedType.of( ArrayList.class );
		String[] boot = TypeHierarchy.supertypes( type, null );
		String[] app = TypeHierarchy.supertypes( type, TypeHierarchyTest.class.getClassLoader() );
		Assertions.assertNotSame( boot, app );
		Assertions.assertArrayEquals( boot, app );
	}
}
