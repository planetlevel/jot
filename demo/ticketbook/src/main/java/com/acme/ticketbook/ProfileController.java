package com.acme.ticketbook;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@SuppressWarnings("serial")
public class ProfileController extends HttpServlet {

	public static String TICKET = "ticket";
	public static String CREDITCARD = "creditcard";
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		if ( request.getParameter( "name" ) != null ) {
			Ticket p = new Ticket( request );
			TicketService.instance().create( p );
			request.setAttribute( TICKET, p );
		}
		
		// forward to view
		getServletContext().getRequestDispatcher("/profile.jsp").forward(request, response);
	}
	
}
