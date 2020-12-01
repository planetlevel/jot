package org.openolly;

import java.util.BitSet;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class JUnitFailTest {

	@Test
	void testJUnit() throws Exception {
		int n = 12345;

		// You can use JOT to fail test cases when a sensor fires!
		// Add the <--- lines to your JOT sensor like this....
		// - name: "test-junit"
		//   description: "Identifies errors detected during JUnit test cases"
		//   methods:
		//   - "java.util.BitSet.<init>"
		//   - "java.util.BitSet.valueOf"
		//   scopes:
		//   - "org.junit.platform.commons.util.ReflectionUtils.invokeMethod"   <---
		//   captures:
		//   - "#OBJ"
		//   exception: "BitSet use is prohibited by Security Directive 27B/6"  <---

		Assertions.assertThrows(NumberFormatException.class, () -> {
			Integer.parseInt("One");
			BitSet bs = BitSet.valueOf(new long[]{n});
			long l = bs.toLongArray()[0];
			Assertions.assertEquals( 12345, l );		
		});
	}
   
}
