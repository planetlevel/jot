package org.openolly.config;

import java.io.IOException;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.openolly.reporting.Event;

public class GraphSerializer {
		
	public static String serialize( Set<Event> events ) throws IOException {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();		 
		String jsonString = gson.toJson(events);
		return jsonString;
	}

	public static Object deserialize( String jsonString ) throws IOException {
		return null;
	}
	
}
