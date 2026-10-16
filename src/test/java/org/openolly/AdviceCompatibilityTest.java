package org.openolly;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Handle;

/**
 * Advice is copied into the methods JOT instruments, including methods of old libraries compiled
 * for Java 6, whose class files can't hold invokedynamic. If any advice contains one, JOT fails
 * to instrument those classes and says nothing unless jot.verbose is on.
 */
class AdviceCompatibilityTest {

	@Test
	void adviceClassesContainNoInvokeDynamic() throws IOException {
		File dir = new File( "target/classes/org/openolly/advice" );
		File[] classes = dir.listFiles( ( d, name ) -> name.endsWith( "Advice.class" ) );
		Assertions.assertNotNull( classes, "advice classes not found in " + dir.getAbsolutePath() );
		Assertions.assertTrue( classes.length > 0 );

		List<String> offenders = new ArrayList<String>();
		for ( File f : classes ) {
			new ClassReader( Files.readAllBytes( f.toPath() ) ).accept( new ClassVisitor( Opcodes.ASM9 ) {
				@Override
				public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
					return new MethodVisitor( Opcodes.ASM9 ) {
						@Override
						public void visitInvokeDynamicInsn(String n, String d, Handle bsm, Object... args) {
							offenders.add( f.getName() + "." + name );
						}
					};
				}
			}, 0 );
		}
		Assertions.assertTrue( offenders.isEmpty(),
				"invokedynamic in advice, build with -XDstringConcat=inline and avoid lambdas: " + offenders );
	}

}
