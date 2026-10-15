package org.openolly;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openolly.advice.ScopeCtorWrapper;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.bytebuddy.pool.TypePool;

/**
 * Checks that constructor scopes are entered after super()/this() and always left,
 * including when the constructor throws.
 */
public class ScopeCtorWrapperTest {

	public static class Target {
		public static boolean boom() { throw new IllegalStateException("arg boom"); }

		public Target(Runnable inside) { inside.run(); }
		public Target(boolean fail) { if (fail) throw new IllegalStateException("body boom"); }
		public Target(String s) { this(boom()); }   // throws while evaluating this(...) args
		public Target(long l, double d, String s, int[] a, boolean early) {
			if (early) return;
			throw new IllegalStateException("wide boom");
		}
	}

	private Sensor sensor;
	private Class<?> scoped;

	@BeforeEach
	public void setUp() throws Exception {
		sensor = new Sensor().method("a.B.m").scope("x.Y.<init>");
		TypeDescription td = TypePool.Default.ofSystemLoader().describe(Target.class.getName()).resolve();
		scoped = new ByteBuddy()
				.redefine(td, ClassFileLocator.ForClassLoader.ofSystemLoader())
				.name(Target.class.getName() + "$Scoped")
				.visit(new AsmVisitorWrapper.ForDeclaredMethods().constructor(isConstructor(),
						new ScopeCtorWrapper(sensor.getIndex(), 0)))
				.make()
				.load(getClass().getClassLoader(), ClassLoadingStrategy.Default.WRAPPER)
				.getLoaded();
	}

	private int depth() {
		return sensor.scopeScopeValue(0);
	}

	private void construct(Class<?>[] types, Object... args) throws Exception {
		Constructor<?> c = scoped.getConstructor(types);
		try {
			c.newInstance(args);
		} catch (InvocationTargetException e) {
			Assertions.assertTrue(e.getCause() instanceof IllegalStateException);
		}
	}

	@Test
	public void testInScopeInsideBodyAndLeftAfter() throws Exception {
		int[] seen = { -1 };
		construct(new Class<?>[] { Runnable.class }, (Runnable) () -> seen[0] = depth());
		Assertions.assertEquals(1, seen[0]);
		Assertions.assertEquals(0, depth());
	}

	@Test
	public void testLeftWhenBodyThrows() throws Exception {
		construct(new Class<?>[] { boolean.class }, true);
		Assertions.assertEquals(0, depth());
	}

	@Test
	public void testNotLeakedWhenThisArgumentsThrow() throws Exception {
		construct(new Class<?>[] { String.class }, "x");
		Assertions.assertEquals(0, depth());
	}

	@Test
	public void testWideArgumentsAndEarlyReturn() throws Exception {
		Class<?>[] types = { long.class, double.class, String.class, int[].class, boolean.class };
		construct(types, 1L, 2.0, "s", new int[1], true);
		Assertions.assertEquals(0, depth());
		construct(types, 1L, 2.0, "s", new int[1], false);
		Assertions.assertEquals(0, depth());
	}
}
