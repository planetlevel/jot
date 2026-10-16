package org.openolly;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.utility.JavaModule;

/**
 * Keeps JotScope held while a class is being looked at for instrumentation. Deciding what to instrument means reading
 * class files, opening jars and verifying their signatures, and with classes such as java.io.File and
 * java.security.MessageDigest instrumented that work would be seen by the sensors, and JOT would end up observing its
 * own machinery. onComplete is called for every class that onDiscovery was, whatever happened to it.
 */
public class JotScopeListener extends AgentBuilder.Listener.Adapter {

	@Override
	public void onDiscovery(String typeName, ClassLoader classLoader, JavaModule module, boolean loaded) {
		JotScope.enter();
	}

	@Override
	public void onComplete(String typeName, ClassLoader classLoader, JavaModule module, boolean loaded) {
		JotScope.exit();
	}

}
