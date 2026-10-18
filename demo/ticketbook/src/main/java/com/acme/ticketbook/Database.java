package com.acme.ticketbook;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class Database {

	private static Database instance = new Database();
	private boolean initialized = false;
		
	public static Database getInstance() {
		if ( instance == null ) {
			instance = new Database();
		}
		return instance;
	}
	
		
	private Database() {
		if ( !initialized ) {
			try {
				Class.forName("org.hsqldb.jdbcDriver");
			} catch (ClassNotFoundException e1) {
				e1.printStackTrace();
			}
			try {
				init();
			} catch( Exception e ) {
				e.printStackTrace();
			}
		}
		initialized = true;
	}
	
	
	private Connection conn;
	public Connection getConnection() {
		
		try {
			if ( conn != null ) {
				if ( !conn.isClosed() ) {
					return conn;
				}
			}
		
			conn = DriverManager.getConnection("jdbc:hsqldb:mem:ticketdb", "sa", "");
		} catch (SQLException e2) {
			e2.printStackTrace();
		}
		return conn;
	}
	
	
	public void closeConnection( Connection conn ) {
		try {
			conn.close();
		} catch (SQLException e) {
		}
	}
	
	
	public void closeResultSet( ResultSet rs ) {
		try {
			rs.close();
		} catch (SQLException e) {
		}
	}
	
	public void init() throws SQLException {

		try {
			updateUnsafe("DROP TABLE tickets" );
		} catch (SQLException e) {
		}

		try {
			updateUnsafe("CREATE TABLE tickets ( id INTEGER IDENTITY, name VARCHAR(64), city VARCHAR(64), cc VARCHAR(64), ticket VARCHAR(16) )");
		} catch (SQLException e) {
			e.printStackTrace();
		}

		// add some rows - will create duplicates if run more then once
		createTicket( new Ticket( "Jeff Williams", "Washington DC", "1234-1234-1234-1234" ) );
		createTicket( new Ticket( "Arshan Dabirsiaghi", "Baltimore", "3456-3456-3456-3456" ) );
		createTicket( new Ticket( "Harold McGinnis", "Philadelphia", "4567-4567-4567-4567" ) );
		createTicket( new Ticket( "Chris Schmidt", "Denver", "5678-5678-5678-5678" ) );

		dump( "tickets" );
	}

	public void shutdown() throws SQLException {
		Connection conn = getConnection();
		Statement st = conn.createStatement();
		st.execute("SHUTDOWN");
		closeConnection( conn );
	}

	
	
	
	// *** UNSAFE ***
	public synchronized ResultSet queryUnsafe(String sql) throws SQLException {
		Connection conn = getConnection();
		Statement st = conn.createStatement();
		ResultSet rs = st.executeQuery(sql);
		return rs;
	}

	// *** SAFE ***
	public synchronized ResultSet querySafe(String sql, String... params) throws SQLException {
		Connection conn = getConnection();		
		PreparedStatement st = conn.prepareStatement( sql );
		for ( int i = 0; i < params.length; i++ ) {
			st.setString( i+1, params[i] );
		}
		ResultSet rs = st.executeQuery();
		return rs;
	}


	
	
	// *** UNSAFE ***
	public synchronized void updateUnsafe(String sql) throws SQLException {
		Connection conn = getConnection();
		Statement st = conn.createStatement();
		st.executeUpdate(sql);
		closeConnection( conn );
	}

	// *** SAFE ***
	public synchronized void updateSafe(String sql, String... params) throws SQLException {
		Connection conn = getConnection();
		PreparedStatement st = conn.prepareStatement( sql );
		for ( int i = 0; i < params.length; i++ ) {
			st.setString( i+1, params[i] );
		}
		st.executeUpdate();
		closeConnection( conn );
	}

	
	
	public void dump(String table) {
		try {
			ResultSet rs = queryUnsafe("SELECT * FROM " + table );
			ResultSetMetaData meta = rs.getMetaData();
			int colmax = meta.getColumnCount();
			int i;
			Object o = null;
	
			for (; rs.next();) {
				for (i = 0; i < colmax; ++i) {
					o = rs.getObject(i + 1);
					System.out.print(o.toString() + " ");
				}
	
				System.out.println(" ");
			}
			closeResultSet( rs );
		} catch( SQLException e ) {
		}
	}

	public void createTicket(Ticket t) {
		System.out.println( "Creating " + t.getTicket() + "::" + t.getName() );
		Connection conn = getConnection();
		try {

			// CONTRAST SQL INJECTION FIX		
		    updateUnsafe("INSERT INTO tickets(name,city,cc,ticket) VALUES('"+t.getName()+"', '"+t.getCity()+"', '"+t.getCreditCard()+"', '"+t.getTicket()+"')");
			// updateSafe("INSERT INTO tickets(name,city,cc,ticket) VALUES(?,?,?,?)", t.getName(), t.getCity(), t.getCreditCard(), t.getTicket() );
			
		} catch( SQLException e ) {
			e.printStackTrace();
		} finally {
			closeConnection( conn );
		}
	}

	public List<Ticket> getTickets() {
		List<Ticket> list = new ArrayList<>();
		Connection conn = getConnection();
		try {
			ResultSet rs = queryUnsafe("SELECT * FROM tickets");
			while ( rs.next() ) {
				Ticket t = new Ticket( rs.getString("name"), rs.getString("city"), rs.getString("cc"), rs.getString( "ticket" ) );
				list.add( t );
			}
		} catch( SQLException e ) {
			
		} finally {
			closeConnection( conn );
		}
		return list;
	}
	
	public Ticket getTicket(String ticket) {
		try {
			
			// CONTRAST SQL INJECTION FIX		
			ResultSet rs = queryUnsafe("SELECT * FROM tickets WHERE ticket='"+ticket+"'");
			// ResultSet rs = querySafe("SELECT * FROM tickets WHERE ticket=?", ticket);
			
			if ( rs.next() ) {
				Ticket t = new Ticket( rs.getString("name"), rs.getString("city"), rs.getString("cc"), rs.getString( "ticket" ) );
				return t;
			}
			rs.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

}