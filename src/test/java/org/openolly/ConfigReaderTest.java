package org.openolly;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.Sensor;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.Reporter;

class ConfigReaderTest {

	@Test
	void readerTest() throws IOException {
		File ruleDir = new File("src/test/resources/rules");;
		ConfigReader.init( ruleDir.getAbsolutePath() );
		Assertions.assertEquals(21, Sensor.getSensors().size() );
		Assertions.assertEquals(12, Reporter.getReports().size() );
	}

	
}

