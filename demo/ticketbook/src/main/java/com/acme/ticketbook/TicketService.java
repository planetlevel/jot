package com.acme.ticketbook;

import org.apache.log4j.Logger;

public class TicketService {
	
	private static TicketService instance = null;
	private static Database database = Database.getInstance();
	
	public static TicketService instance() {
		if ( instance == null ) {
			instance = new TicketService();
			instance.initialize();
		}
		return instance;
	}

	public void create(Ticket t) {
		if ( t != null && !t.equals(Ticket.ANONYMOUS )) {
			database.createTicket( t );
		}
	}
	
	public Ticket get( String key ) {
		if ( key == null ) {
			return Ticket.ANONYMOUS;
		}
		Ticket p = database.getTicket( key );
		return ( p==null ? Ticket.ANONYMOUS : p );
	}
	
	public void initialize() {
		System.setProperty( "algorithm", "DES" );
		org.apache.log4j.BasicConfigurator.configure();
		Logger.getLogger(TicketService.class).debug( "Initializing ProfileController" );
	}

}
