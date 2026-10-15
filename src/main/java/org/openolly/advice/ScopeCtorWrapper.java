package org.openolly.advice;

import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import net.bytebuddy.pool.TypePool;

/**
 * Tracks a JOT scope around the body of a constructor.
 *
 * Byte Buddy's Advice can't do this. Its enter advice runs before the super() or this() call,
 * and its exit advice can't catch exceptions in a constructor. Both are because the JVM verifier
 * won't accept an exception handler that spans the point where "this" becomes initialized.
 *
 * Instead the scope is entered right AFTER the super()/this() call and an exception handler
 * covers only the rest of the constructor, so the scope is always left, even if the constructor
 * throws. An exception thrown while evaluating the super()/this() arguments never entered the
 * scope, so there is nothing to leave. The scope therefore covers the constructor body, not the
 * arguments to super()/this().
 */
public class ScopeCtorWrapper implements AsmVisitorWrapper.ForDeclaredMethods.MethodVisitorWrapper {

	private static final String SENSOR = "org/openolly/Sensor";

	private final int sensorIndex;
	private final int scopeIndex;

	public ScopeCtorWrapper(int sensorIndex, int scopeIndex) {
		this.sensorIndex = sensorIndex;
		this.scopeIndex = scopeIndex;
	}

	@Override
	public MethodVisitor wrap(TypeDescription instrumentedType, MethodDescription instrumentedMethod,
			MethodVisitor methodVisitor, Implementation.Context implementationContext, TypePool typePool,
			int writerFlags, int readerFlags) {
		boolean expandedFrames = (readerFlags & ClassReader.EXPAND_FRAMES) != 0;
		return new ScopeVisitor(methodVisitor, instrumentedType.getInternalName(), instrumentedMethod.getDescriptor(), expandedFrames);
	}

	private class ScopeVisitor extends MethodVisitor {

		private final String owner;
		private final String descriptor;
		// ASM can't mix expanded (F_NEW) and compressed frames in one method, so match the reader
		private final boolean expandedFrames;
		private final Label end = new Label();
		private final Label handler = new Label();
		// number of "new" instructions whose constructor call hasn't been seen yet
		private int pendingNews = 0;
		private boolean inBody = false;

		ScopeVisitor(MethodVisitor mv, String owner, String descriptor, boolean expandedFrames) {
			super(Opcodes.ASM9, mv);
			this.owner = owner;
			this.descriptor = descriptor;
			this.expandedFrames = expandedFrames;
		}

		@Override
		public void visitTypeInsn(int opcode, String type) {
			if (opcode == Opcodes.NEW && !inBody) pendingNews++;
			super.visitTypeInsn(opcode, type);
		}

		@Override
		public void visitMethodInsn(int opcode, String methodOwner, String name, String desc, boolean isInterface) {
			super.visitMethodInsn(opcode, methodOwner, name, desc, isInterface);
			if (inBody || opcode != Opcodes.INVOKESPECIAL || !name.equals("<init>")) return;
			if (pendingNews > 0) {
				pendingNews--; // constructor call for an object created in the arguments
				return;
			}
			// this was the super() or this() call, "this" is initialized from here on
			inBody = true;
			Label start = new Label();
			// must be declared before the labels are visited
			super.visitTryCatchBlock(start, end, handler, null);
			super.visitLabel(start);
			callScope("enterScopeScope");
		}

		@Override
		public void visitInsn(int opcode) {
			if (inBody && opcode == Opcodes.RETURN) callScope("leaveScopeScope");
			super.visitInsn(opcode);
		}

		@Override
		public void visitMaxs(int maxStack, int maxLocals) {
			if (inBody) {
				super.visitLabel(end);
				super.visitLabel(handler);
				// locals are "this" and the arguments. Anything the body adds is simply unusable here.
				Type[] args = Type.getArgumentTypes(descriptor);
				Object[] locals = new Object[args.length + 1];
				locals[0] = owner;
				for (int i = 0; i < args.length; i++) locals[i + 1] = frameType(args[i]);
				super.visitFrame(expandedFrames ? Opcodes.F_NEW : Opcodes.F_FULL, locals.length, locals, 1, new Object[] { "java/lang/Throwable" });
				callScope("leaveScopeScope");
				super.visitInsn(Opcodes.ATHROW);
				maxStack = Math.max(maxStack, 3);
			}
			super.visitMaxs(maxStack, maxLocals);
		}

		private void callScope(String method) {
			super.visitLdcInsn(sensorIndex);
			super.visitLdcInsn(scopeIndex);
			super.visitMethodInsn(Opcodes.INVOKESTATIC, SENSOR, method, "(II)V", false);
		}

		private Object frameType(Type t) {
			switch (t.getSort()) {
			case Type.BOOLEAN: case Type.BYTE: case Type.CHAR: case Type.SHORT: case Type.INT:
				return Opcodes.INTEGER;
			case Type.FLOAT: return Opcodes.FLOAT;
			case Type.LONG: return Opcodes.LONG;
			case Type.DOUBLE: return Opcodes.DOUBLE;
			case Type.ARRAY: return t.getDescriptor();
			default: return t.getInternalName();
			}
		}
	}
}
