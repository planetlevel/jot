package org.openolly;

/**
 * Marks a thread as running JOT's own code. While it is, no sensor fires, whichever sensor it is.
 *
 * Evaluating a capture calls into the application, for example toString() on a captured object,
 * and delivering events opens files and sockets. Both can reach methods that have sensors on them,
 * so without this JOT would end up observing, or even blocking, itself.
 *
 * This is one flag per thread and is shared by all sensors.
 */
public final class JotScope {

	private static final ThreadLocal<int[]> depth = ThreadLocal.withInitial( () -> new int[1] );

	private JotScope() {
	}

	/** True if this thread is running JOT code. */
	public static boolean active() {
		return depth.get()[0] > 0;
	}

	/** Enter JOT code. Always pair with exit() in a finally block. */
	public static void enter() {
		depth.get()[0]++;
	}

	public static void exit() {
		depth.get()[0]--;
	}

	/** For a thread that only ever runs JOT code, such as the event delivery thread. */
	public static void enterForThread() {
		enter();
	}

}
