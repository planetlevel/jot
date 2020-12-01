package org.openolly;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.reporting.Trace;

class TraceTest {

	@Test
	void testTrace() throws Exception {
		final List<Integer> list = new ArrayList<Integer>();
//		for ( int i=0; i<100; i++ ) {
//			Thread t = new Thread(new Runnable() {
//				@Override public void run() {
//					Event e = new Event("rule" + Thread.currentThread().getName(),"caller",Thread.currentThread().getName());
//					Trace.getCurrentTrace().addEvent(e);
//					Trace.getCurrentTrace().addEvent(e);
//					Trace.getCurrentTrace().addEvent(e);
//					Trace.getCurrentTrace().printTrace();
//				}
//			});
//			t.start();
//			list.add( Trace.getCurrentTrace().getSize());
//		}
//		Thread.sleep(2000);
//		for( Integer i : list ) {
//			System.out.println( ">" + i );
//			Assertions.assertEquals(3, i);
//		}
	}
	
	
	@Test
	void testTrace2() throws Exception {
		for ( int i=0; i<100; i++ ) {
			Thread t = new Thread(new Runnable() {
				SecureRandom rng = new SecureRandom();
				@Override public void run() {
					int tid = Trace.getCurrentTrace().getId();
					for (int b=0; b<10; b++ ) {
						try {
							Thread.sleep( rng.nextInt() * 100 );
							Assertions.assertEquals(tid, Trace.getCurrentTrace().getId() );
						} catch( Exception e ) {}
					}
				}
			});
			t.start();
		}
	}

}

