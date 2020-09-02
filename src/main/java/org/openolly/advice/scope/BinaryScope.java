package org.openolly.advice.scope;

public final class BinaryScope {

	private final ThreadLocal<Counter> counters = new ThreadLocal<Counter>() {
		@Override
		protected Counter initialValue() {
			return new Counter();
		}
	};

	public boolean inScope() {
		return counters.get().value != 0;
	}

	public boolean inOutermostScope() {
		return counters.get().value == 1;
	}

	public boolean inNestedSensor() {
		return counters.get().value > 1;
	}

	public int value() {
		return counters.get().value;
	}

	public void enterScope() {
		counters.get().value++;
	}

	public void leaveScope() {
		counters.get().value--;
	}

	public void reset() {
		counters.get().value = 0;
	}

	@Override
	public String toString() {
		return String.valueOf(value());
	}

	private static final class Counter {
		private int value;
	}
}