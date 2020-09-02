package org.openolly.config;

import java.util.Timer;
import java.util.TimerTask;

public class ConfigMonitor extends TimerTask {

	public void start() {
		// FIXME: look into WatchService
		new Timer().scheduleAtFixedRate( this, 10*1000, 10*1000);
		System.out.println( "[SENSOR] Monitoring yaml configuration for changes" );
	}
	
	public void run() {
//		try {
//			// FIXME - this won't work until retransformation is enabled
//			if ( ConfigReader.isChanged() ) {
//				ConfigReader.load();
//			}
//		} catch( Exception e ) {
//			System.out.println( "Error checking yaml... continuing with old config" );
//			e.printStackTrace();
//		}
		
		
	}

}
