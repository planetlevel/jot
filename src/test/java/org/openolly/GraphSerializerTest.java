package org.openolly;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;

import com.google.common.graph.Graph;
import com.google.common.graph.GraphBuilder;
import com.google.common.graph.MutableGraph;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openolly.config.GraphSerializer;
import org.openolly.reporting.Event;
import org.openolly.reporting.RouteGraph;

class GraphSerializerTest {

	@Test
	void testSerialize() {
		try {
			MutableGraph<Event> g = GraphBuilder.directed().allowsSelfLoops(true).build();
			Event a = new Event("a","capture",Thread.currentThread().getStackTrace());
			Event b = new Event("b","capture",Thread.currentThread().getStackTrace());
			Event c = new Event("c","capture",Thread.currentThread().getStackTrace());
			Event d = new Event("d","capture",Thread.currentThread().getStackTrace());
			g.putEdge(a,b);
			g.putEdge(a,c);
			g.putEdge(b,d);
			g.putEdge(c,d);
			System.err.println( ">>>" + g.edges() );
			String jsonString = GraphSerializer.serialize( g.nodes() );
			RouteGraph.dump(g);
			System.out.println( "==SERIALIZED==");
			System.out.println( jsonString );
			//Graph x = GraphSerializer.deserialize( jsonString );
		} catch( Exception e ) {
			e.printStackTrace();
		}
	}

}
