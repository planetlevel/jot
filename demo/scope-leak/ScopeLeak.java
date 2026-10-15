public class ScopeLeak {
	static class Vuln {
		Vuln() {}
		Vuln(Runnable inside) { inside.run(); }
		Vuln(boolean fail) { if (fail) throw new IllegalStateException("ctor boom"); }
		static int boom() { throw new IllegalStateException("arg boom"); }
		Vuln(String s) { this(boom() > 0); }   // throws while evaluating this(...) args
		// awkward argument types and an early return, to exercise the constructor handler frame
		Vuln(long l, double d, String s, int[] arr, boolean early, Runnable inside) {
			if (early) { if (inside != null) inside.run(); return; }
			if (inside != null) inside.run();
			throw new IllegalStateException("wide ctor boom " + l + d + s + arr.length);
		}
		static void method(boolean fail, Runnable inside) {
			if (inside != null) inside.run();
			if (fail) throw new IllegalStateException("method boom");
		}
	}
	static class Danger { static String call() { return "ok"; } }

	static boolean blocked(Runnable r) { try { r.run(); return false; } catch (Throwable t) { return t.getClass().getSimpleName().equals("SensorException"); } }
	static void expect(String label, boolean cond) { System.out.println((cond ? "PASS  " : "FAIL  ") + label); }

	public static void main(String[] a) {
		boolean method = a[0].equals("method");
		expect("baseline outside scope allowed", !blocked(Danger::call));
		if (method) expect("inside scope blocked", blocked(() -> Vuln.method(false, Danger::call)));
		else        expect("inside scope blocked", blocked(() -> new Vuln(Danger::call)));
		try { Vuln.method(true, null); } catch (RuntimeException e) {}
		expect("allowed after method threw", !blocked(Danger::call));
		try { new Vuln(true); } catch (RuntimeException e) {}
		expect("allowed after ctor body threw", !blocked(Danger::call));
		try { new Vuln("x"); } catch (RuntimeException e) {}
		expect("allowed after ctor this(...) args threw", !blocked(Danger::call));
		try { new Vuln(1L, 2.0, "s", new int[1], false, null); } catch (RuntimeException e) {}
		expect("allowed after ctor with long/double/array args threw", !blocked(Danger::call));
		new Vuln(1L, 2.0, "s", new int[1], true, null);
		expect("allowed after ctor returned early", !blocked(Danger::call));
		if (!method) expect("early-return ctor still blocks inside", blocked(() -> new Vuln(1L, 2.0, "s", new int[1], true, Danger::call)));
		if (method) expect("blocked again in later scope entry", blocked(() -> Vuln.method(false, Danger::call)));
		else        expect("blocked again in later scope entry", blocked(() -> new Vuln(Danger::call)));
	}
}
