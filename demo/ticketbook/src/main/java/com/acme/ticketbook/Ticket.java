package com.acme.ticketbook;

import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import jakarta.servlet.ServletRequest;

import org.apache.log4j.Logger;

public class Ticket {

	public String name = "Anonymous";
	public String city = "Washington-DC";
	public String creditcard = "";
	private String ticket = "";
	private static Key key = null;
	private static String algorithm = "";
	private static int count = 10000;
	public static Ticket ANONYMOUS = new Ticket( "Anonymous", "Nowhere", "0000-0000-0000-0000" );

	
	
	
	public Ticket(String name, String city, String cc ) {
		initialize();
		setName( name );
		setCity( city );
		setCreditCard( cc );
		setTicket( ""+count++ );
	}
	
	public Ticket(ServletRequest request) {
		initialize();
		String name = request.getParameter( "name" );
		String city = request.getParameter( "city" );
		String cc = request.getParameter( "cc" );
		setName( name );
		setCity( city );
		setCreditCard( cc );
		setTicket( ""+count++ );
		Logger.getLogger(Ticket.class).debug( "Created Ticket: " + getName() );
	}

	public Ticket(String name, String city, String cc, String ticket) {
		initialize();
		setName( name );
		setCity( city );
		setCreditCard( cc );
		setTicket( ticket );
	}

	public String getName() {
		return name;
	}
	
	public void setName( String name ) {
		if ( name != null ) {
			this.name = name;
		}
	}

	public String getCity() {
		return city;
	}

	private void setCity(String city) {
		this.city = city;
	}

	public String getTicket() {
		return ticket;
	}

	public void setTicket(String ticket) {
		this.ticket = ticket;
	}
	
	public String getCreditCard() {
		return creditcard;
	}

	public void setCreditCard(String cc) {
		if ( cc != null ) {
			this.creditcard = encrypt(cc);
		}
	}
	
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append( "{\n" );
		sb.append( "  \"person\" : {\n");
		sb.append( "    \"name\" : \"" + getName().toUpperCase() + "\",\n" );
		sb.append( "    \"city\" : \"" + getCity() + "\",\n" );
		sb.append( "    \"cred\" : \"" + getCreditCard() + "\"\n" );
		sb.append( "    \"ticket\" : \"" + getTicket() + "\"\n" );
		sb.append( "  }\n");
		sb.append( "}\n");
		return sb.toString();
	}

	public static void initialize() {
		try {
			algorithm = System.getProperty( "algorithm", "DES" );
			DESKeySpec keyspec = new DESKeySpec("supersecretpassword".getBytes());
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance( algorithm );
			key = keyFactory.generateSecret(keyspec);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static String encrypt(String str) {
		try {
			Cipher cipher = Cipher.getInstance( algorithm );
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encrypted = cipher.doFinal(str.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
