/*
CheckPassword a password checker for MyWebProject
Copyright (C) 2017-2018 Davide Sestili

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package it.dsestili.chkpwd;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Base64;
import java.util.Formatter;

public class CheckPassword 
{
	private Connection connection = null;
	private static final String PROP_FILE_NAME = "config.properties";
	
	public static void main(String[] args) 
	{
		if(args.length != 2)
		{
			System.out.println("Usage: param 1: userName, param 2: password");
		}
		else
		{
			CheckPassword chkPwd = new CheckPassword();
			String base_dir = chkPwd.checkPassword(args[0], args[1]);
			System.out.println(base_dir);
		}
	}

	public String checkPassword(String userName, String password)
	{
		String result = null;
		
		openConnection();
		
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			
			String queryGetPassword = getProperty("query.getPassword");
			
			PreparedStatement statement = connection.prepareStatement(queryGetPassword);
			statement.setString(1, userName);
			ResultSet rs = statement.executeQuery();
			if(rs.next())
			{
				String dbPwd = rs.getString(1);
				
				md.update(password.getBytes());
				byte[] data = md.digest();
				password = byteArray2Hex(data);
				
				if(password.equalsIgnoreCase(dbPwd))
				{
					String queryGetBaseDir = getProperty("query.getBaseDir.utenti");
					
					statement = connection.prepareStatement(queryGetBaseDir);
					statement.setString(1, userName);
					rs = statement.executeQuery();
					rs.next();
					result = rs.getString(1);
				}
			}
		}
		catch(Exception e)
		{
			System.out.println("Si è verificato un errore: " + e.getMessage());
		}
		
		closeConnection();
		
		return result;
	}

	private String byteArray2Hex(byte[] hash) 
	{
	    Formatter formatter = new Formatter();
	    
	    for(byte b : hash) 
	    {
	        formatter.format("%02x", b);
	    }
	    
	    String result = formatter.toString();
	    formatter.close();
	    return result;
	}
	
	private String getProperty(String key)
	{
		Properties prop = new Properties();
		InputStream input = null;
		String value = null;

		try
		{
			input = CheckPassword.class.getClassLoader().getResourceAsStream(PROP_FILE_NAME);
			
			if(input == null)
			{
				System.out.println("File di properties non trovato " + PROP_FILE_NAME);
				return null;
			}

			prop.load(input);
			value = prop.getProperty(key);
		}
		catch(IOException e)
		{
			System.out.println("Errore di lettura dal file di properties: " + e.getMessage());
		}
		finally
		{
			if(input != null)
			{
				try 
				{
					input.close();
				} 
				catch(IOException e) 
				{
					System.out.println("Errore di chiusura input stream: " + e.getMessage());
				}
			}
		}
		
		return value;
	}
	
	private void openConnection()
	{
		if(connection == null)
		{
			try 
			{
				Class.forName("com.mysql.jdbc.Driver");
				
				String connectionString = getProperty("connectionString");
				String userName = decodeBase64(getProperty("userName"));
				String password = decodeBase64(getProperty("password"));
				
				connection = DriverManager.getConnection(connectionString, userName, password);
				System.out.println("Connessione riuscita");
			}
			catch(SQLException e) 
			{
				System.out.println("Errore di connessione: " + e.getMessage());
			} 
			catch(ClassNotFoundException e) 
			{
				System.out.println("Errore di connessione: " + e.getMessage());
			}
		}
	}
	
	private String decodeBase64(String enc)
	{
		byte[] decodedBytes = Base64.getDecoder().decode(enc);
		return new String(decodedBytes);
	}
	
	private void closeConnection()
	{
		if(connection != null)
		{
			try 
			{
				connection.close();
				connection = null;
				System.out.println("Connessione chiusa");
			} 
			catch(SQLException e) 
			{
				System.out.println("Errore di chiusura connessione: " + e.getMessage());
			}
		}
	}
}
