package org.openolly;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.config.ConfigReader;
import org.openolly.reporting.Reporter;

class ConfigReaderTest {

	@Test
	void readerTest() throws IOException {
		File ruleDir = new File("src/test/resources/rules");;
		ConfigReader.init( ruleDir.getAbsolutePath() );
		//Assertions.assertEquals(22, Sensor.getSensors().size() );
		//Assertions.assertEquals(14, Reporter.getReports().size() );
	}

	
}

