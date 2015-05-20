import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;


public class Sync {	
		//TODO: Move Variables to properties file
		//Initialize Logger
	//TODO: Fix Logger pulling appropriate configuration file
	private static final Logger log = LogManager.getLogger(Sync.class);
	
	public static void main(String[] args) throws Exception { 
		log.trace("Configuration File Defined To Be :: "+System.getProperty("log4j.configurationFile"));
		log.trace("Entering Application.");

		log.trace("MAIN IS EXECUTING");


		JSONObject  ldap = queryLDAP("something");
		
		// ldap is a JSONObject with format {group : {[name],[LDIF]},{[],[]}...}
		for (int i =0 ; i < ldap.length(); i++)
		{
			String group = ldap.names().getString(i);
			String token = getToken();
			String link = getGroupId(group,token);
			String users = link + "/users";
			System.out.println("Iteration 2 length : " + ldap.getJSONArray(group).length());
			System.out.println("\nget project id : " + users + "\n" + token);
			for(int j = 0; j < ldap.getJSONArray(group).length(); j++ )
			{
							
				addUser(ldap, j, link, token);
			}		
			
		}

		//TODO: try bulk loading ldap to keystone
	
	}

	private static void addUser(JSONObject user,int j, String groupLink, String token) throws IOException, JSONException{
		   
		   String name = user.getJSONArray(user.names().getString(0)).getJSONObject(j).getString("name");
		   JSONObject member = user.getJSONArray(user.names().getString(0)).getJSONObject(j);
		   String userExists = userExist(name, token);
		   if(userExists != null)
		   {
			   // CASE 1: User exists 
			   log.trace(userExists);

			   if(userInGroup(name,groupLink,token)){
				   // Case 1A: User exists in group
				   log.trace("Got into user Exist, User In Group");
				   
				   // doNothing();			   
			   }
			   else{
				   // CASE 1B: User exists not in group
				   log.trace("Got into user Exist, User not In Group");
				   addUserToGroup(userExists,groupLink,token);		   
			   }
		   }
		   else
		   {
			   // CASE 2: User doesn't exist
			   System.out.println("Got into user Exist, false");
			   String newuser = createUser(member,token);
			   newuser = newuser.substring(1);
			   System.out.println("new user is " + newuser);
			   userExists = userExist(newuser,token);

			   addUserToGroup(userExists,groupLink,token);
			   
		   }
		   
		   
		   return;
	   }
	
	//IGNORE queryKeyStone work in progress.	
	public static ArrayList<Attribute<String,String[]>> queryKeyStone(String attribute) throws  JSONException, MalformedURLException, IOException {
		if(attribute == "test"){
//			HttpURLConnection httpcon = (HttpURLConnection) ((new URL("http://icp-icocs01.icp.ibm.com:50000/v3/auth/tokens").openConnection()));
			HttpURLConnection httpcon = (HttpURLConnection) ((new URL("http://icp-icocs01.icp.ibm.com:5000/v3/users").openConnection()));
			httpcon.setRequestMethod("POST");
			httpcon.setRequestProperty("Content-Type", "application/json");
			httpcon.setRequestProperty("Accept", "application/json");
			httpcon.setRequestProperty("charset", "utf-8");			

			String a = "{\"token\": {\"methods\": [\"password\"], \"roles\": [{\"id\": \"afba02966a04408183e060fe5f1c25f5\", \"name\": \"KeystoneAdmin\"}, {\"id\": \"9fe2ff9ee4384b1894a90878d3e92bab\", \"name\": \"_member_\"}, {\"id\": \"68408a26a3ae48269d017ad280e321a6\", \"name\": \"admin\"}, {\"id\": \"b6babf49a58247a69e94bb5b49a0b7af\", \"name\": \"KeystoneServiceAdmin\"}], \"expires_at\": \"2015-05-14T20:34:30.580624Z\", \"project\": {\"domain\": {\"id\": \"default\", \"name\": \"Default\"}, \"id\": \"d837659849b2471ab03b20e9527bc6a6\", \"name\": \"admin\"}, \"catalog\": [{\"endpoints\": [{\"url\": \"http://icp-icocs01.icp.ibm.com:35357/v3\", \"region\": \"RegionVMware\", \"interface\": \"admin\", \"id\": \"c669e53b14af4a84bbe5f8df116691aa\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:35357/v3\", \"region\": \"RegionVMware\", \"interface\": \"internal\", \"id\": \"69277c7e8a5c4029aa44b37dc3aa0c5e\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:5000/v3\", \"region\": \"RegionVMware\", \"interface\": \"public\", \"id\": \"6432388c57b7406eb6231f63b4a60cb9\"}], \"type\": \"identity\", \"id\": \"384c23f632f741428aefa93636be79a2\", \"name\": \"keystone\"}, {\"endpoints\": [{\"url\": \"http://icp-icocs01.icp.ibm.com:8774/v2/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"admin\", \"id\": \"f51251eff7f54032a4b9eb04c51b9bd0\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:8774/v2/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"internal\", \"id\": \"0aec142e3aa9426fbbec2003b5bc5846\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:8774/v2/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"public\", \"id\": \"30476020a4ce405e9e775dd45f45bc5d\"}], \"type\": \"compute\", \"id\": \"a79fc26b4dec4fc3921cbe1c43b32d82\", \"name\": \"nova\"}, {\"endpoints\": [{\"url\": \"http://icp-icocs01.icp.ibm.com:9292\", \"region\": \"RegionVMware\", \"interface\": \"admin\", \"id\": \"85349f7c3e84464fb49ea47145ab84ed\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:9292\", \"region\": \"RegionVMware\", \"interface\": \"internal\", \"id\": \"6a27767be7e94703a29a26b1df06af66\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:9292\", \"region\": \"RegionVMware\", \"interface\": \"public\", \"id\": \"4e0438a963e14c21a683783f8ef3eb28\"}], \"type\": \"image\", \"id\": \"fd543ddec0c541c9923cd9790680e724\", \"name\": \"glance\"}, {\"endpoints\": [{\"url\": \"http://icp-icocs01.icp.ibm.com:8776/v1/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"admin\", \"id\": \"1c3c71aea5b8435780ebf28ac062945a\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:8776/v1/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"internal\", \"id\": \"08d11bf16471444ba8d3d60fcbbd1d5a\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:8776/v1/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"public\", \"id\": \"e5bb12b9aaa740b4bf591aae8d245a61\"}], \"type\": \"volume\", \"id\": \"72deecb3757c4f6c9c2863a735749c9b\", \"name\": \"cinder\"}, {\"endpoints\": [{\"url\": \"http://icp-icocs01.icp.ibm.com:8004/v1/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"admin\", \"id\": \"35dc1ce170624b38b910ac5b07895e44\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:8004/v1/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"internal\", \"id\": \"ae75a757d05f4b5587bb87efe75e3d1f\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:8004/v1/d837659849b2471ab03b20e9527bc6a6\", \"region\": \"RegionVMware\", \"interface\": \"public\", \"id\": \"60cd977e9c9a4421901795b2940ee7e9\"}], \"type\": \"orchestration\", \"id\": \"aa5b33205b944395a0790525835a68d0\", \"name\": \"heat\"}, {\"endpoints\": [{\"url\": \"http://icp-icocs01.icp.ibm.com:8000/v1\", \"region\": \"RegionVMware\", \"interface\": \"admin\", \"id\": \"477a53c9a4ac47289453ccd4ff5c3aee\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:8000/v1\", \"region\": \"RegionVMware\", \"interface\": \"internal\", \"id\": \"dc00be1c0b574a39aed17be413a9fd73\"}, {\"url\": \"http://icp-icocs01.icp.ibm.com:8000/v1\", \"region\": \"RegionVMware\", \"interface\": \"public\", \"id\": \"0eabd331ae16415385564ba1dd4225bc\"}], \"type\": \"cloudformation\", \"id\": \"30199950b79847e393542a3e30e459df\", \"name\": \"heat-cfn\"}], \"extras\": {}, \"user\": {\"domain\": {\"id\": \"default\", \"name\": \"Default\"}, \"id\": \"fef8b468f31d4d97a8241eeb58e1109e\", \"name\": \"admin\"}, \"issued_at\": \"2015-05-13T20:34:30.580651Z\"}}";

			JSONObject obj = new JSONObject();
			
			obj.put("X-Auth-Token", obj.stringToValue(a));
			
			httpcon.setDoOutput(true);
			httpcon.setDoInput(true);
			
			String input = obj.toString();

			OutputStream os = httpcon.getOutputStream();
			if(os != null){
				try{
					os.write(input.getBytes());
					os.flush();
					System.out.println("Well, we sent it. " + os.toString());
					
				}
				finally {
					os.close();
					System.out.println("Well, we closed it.");
				}
			}
			else {
				throw new IOException("Output stream is null");
			}
			
			System.out.println("2");

			os.write(input.getBytes());
			System.out.println("3");
			os.flush();
			System.out.println("4");
			
			try {
				if (httpcon.getResponseCode() != HttpURLConnection.HTTP_CREATED){
					throw new RuntimeException("Failed : HTTP error code : "+ httpcon.getResponseCode() + httpcon.getResponseMessage());
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println("5");
			System.out.println(httpcon.getResponseCode());
			System.out.println(httpcon.getResponseMessage());
			
			
			return null;
		}
		else{
			System.out.println("A");

	
		
		
		
//		String uri = "http://icp-icocs01.icp.ibm.com:35357/v3/auth/tokens";
//		String uri = "http://icp-icocs01.icp.ibm.com:50000/v3/auth/tokens";
		String base = "http://icp-icocs01.icp.ibm.com:50000";
		String location = "/v3";	// /auth/tokens
		String charset = "UTF-8";
		
		String param1 = "";			// value1
		String param2 = "";			// value2
		
		String query = "";
				/*/
				String.format("param1=%s&param2=%s", 
				URLEncoder.encode(param1,charset),
				URLEncoder.encode(param2,charset));
				//*/
		
		
		URL url = new URL(base + location + "" + query);
		System.out.println(base + location + "" + query);
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestProperty("Content-Length", "1000");

		connection.setRequestMethod("GET");
		connection.setRequestProperty("Accept","application/json");

		/*/
		//Send Request
		OutputStream outputStream = connection.getOutputStream();
		System.out.println("outputStream Created");
		String jsonRequest = "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"domain\":{\"id\":\"default\"},\"password\":\"passw0rd\"}}}}}";

		outputStream.write(jsonRequest.getBytes());
		System.out.println(jsonRequest);
		outputStream.flush();
//		outputStream.close();
		System.out.println("outputStream closed");
		
//		connection.setDoOutput(false);
				
//		System.out.println("Response =" +connection.getResponseCode());
		//*/
		
		connection.connect();
		
		System.out.println("Looking for response");
				
		System.out.println(connection.getResponseCode());
		System.out.println(connection.getResponseMessage());		
		
		
		if (connection.getResponseMessage() != "") {
			throw new RuntimeException("Failed : HTTP error code : "
					+ connection.getResponseCode());
		}
		

		
		
		
		
		BufferedReader br = new BufferedReader(new InputStreamReader((connection.getInputStream())));
		System.out.println("Do I get here?");
		
		String output;
		System.out.println("Output Starting");
		
		while((output = br.readLine()) != null){
			System.out.println("Reading");

			System.out.println(output);
		}
		
		connection.disconnect();
		
						
		System.out.println();
		return null;
		
	}}
	
	public static LDAPConnection getConnection(String host,int port, String username, String password) throws LDAPException {
	    // Host Name or IP Address, Port Number (389 / 636), Bind User name and Bind Password
		// Working
	    return new LDAPConnection(host, port, username, password);
	}
		
	private static JSONObject queryLDAP(String attribute) throws LDAPException, JSONException{
		// Queries LDAP and returns a JSON Object of groups : members under the scope (CN=IPA*)
		//TODO: Implement Query as a private class
		//TODO: attribute will determine scope
		JSONObject output = new JSONObject();

		int port = 389; 
		String ldapServer = "172.16.3.43";
		String bindID = "CN=Administrator,CN=Users,dc=icp,dc=ibm,dc=com";
		String password = "MinV1kes";
		String base = "dc=icp,dc=ibm,dc=com";
		String scope = "(CN=IPA*)";
				
		LDAPConnection connection = new LDAPConnection(ldapServer,port,bindID,password);
		
		log.trace(connection.toString());

		SearchResult searchResult = connection.search(base,SearchScope.SUB, scope);
		
		log.trace(searchResult.getEntryCount() + " entries returned.");
				//Iterate through Search results			
			for (SearchResultEntry e : searchResult.getSearchEntries())
			{
				//Iterate through each group matching the scope
				RDN distinguishedName = e.getRDN();
				String dn = distinguishedName.toString();
				dn = dn.substring(3);
						
			  	//Pull Attribute 'member' which contains users of DN
				String[] member = e.getAttributeValues("member");
								
				//If 'member' is not empty 
			  if(member != null){
				  //JSON Array used to hold members of group
				  JSONArray jArray = new JSONArray();
				  //Iterate through 'member'
				  for(int i = 0; i < member.length; i++){
					  log.trace("Iteration # " + i );
					  //Search for 'member' in LDAP
					  SearchResultEntry individual = connection.getEntry(member[i]);
					  JSONObject jObject = new JSONObject();
					  jObject.put("name",individual.getDN());
					  JSONObject temp = new JSONObject();
					  String[] array;
					  jObject.put("LDIF",individual.toLDIFString());
					  
					  jArray.put(jObject);
					  
					  log.trace("Parent JSON Object : "  + dn);
					  log.trace("Name in JSON Object : " + individual.getDN());		
					  log.trace("LDIF in JSON Object to LDIFString : " + individual.toLDIFString());
					  log.trace("LDIF in temp Object : " + temp.toString());

					  
				  }
				  output.put(dn, jArray);
			  }
			  else
			  {
				  log.info("No Members found in DN : " + dn);
			  }			  
			}			
			
			log.trace(output.toString());
			return output;			
	}


   public static void addRole() throws JSONException{
   try{
	   String key_admin_url = "http://icp-icocs01.icp.ibm.com:5000/v3/auth/tokens";
	   String tenant_id = "";
	   String user_id = "";
	   String role_id = "";
	   String msg= "Hi Server! Just a quick hello!";
	   
	   URL url = new URL(key_admin_url +  "");
	   HttpURLConnection connection = (HttpURLConnection) url
               .openConnection();
       log.trace("Received a : " + connection.getClass().getName());
       connection.setDoOutput(true);
       connection.setDoInput(true);
       connection.setUseCaches(false);
       connection.setRequestMethod("POST");

       connection.setInstanceFollowRedirects(true);
       connection.setRequestProperty("Content-Type",
               "application/json");
       connection.setRequestProperty("X-Auth-Token",
               "sfIEPUb90LvImkQunhcfDQ==");
//       connection.connect();
       
       checkForErrors(connection);
       
       if (connection.getErrorStream() !=null){
       InputStream err = connection.getErrorStream();
       InputStreamReader esr = new InputStreamReader(err);       
       BufferedReader er = new BufferedReader(esr);
       checkForErrors(connection);
       }else{}
       
       String jsonRequest = "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"domain\":{\"id\":\"default\"},\"password\":\"passw0rd\"}}}}}";

     OutputStream os =  connection.getOutputStream();
     OutputStreamWriter out = new OutputStreamWriter(os);
     			out.write(jsonRequest);
                out.flush();
                out.close();       
       
       checkForErrors(connection);
       
       log.trace(" Headers: " + connection.getHeaderFields());
       
     //read response
       
     InputStream is = connection.getInputStream();
     InputStreamReader isr = new InputStreamReader(is);
     BufferedReader reader = new BufferedReader(isr);
    
       String lines;
       int count =0;
       JSONObject obj = null;
       StringBuffer sb = new StringBuffer("");
       
       while ((lines = reader.readLine()) != null) {
 
    	   lines = new String(lines.getBytes(), "utf-8");
           obj = new JSONObject(lines);
           sb.append(lines);
           System.out.println(count++);
           
       }

       reader.close();     

       // disconnect
       connection.disconnect();
      } catch (MalformedURLException e) {
       // TODO Auto-generated catch block
       e.printStackTrace();
   } catch (UnsupportedEncodingException e) {
       // TODO Auto-generated catch block
       e.printStackTrace();
   } catch (IOException e) {
       // TODO Auto-generated catch block
       e.printStackTrace();
   }
}
	
   private static void checkForErrors(HttpURLConnection connection){
	   // Working
       if (connection.getErrorStream() !=null){
       InputStream err = connection.getErrorStream();
       InputStreamReader esr = new InputStreamReader(err);       
       BufferedReader er = new BufferedReader(esr);
 
       String error;
       StringBuffer eb = new StringBuffer("");
       
       try {
    	   while ((error = er.readLine()) != null) {
		       error = new String(error.getBytes(), "utf-8");
		       eb.append(error);
		   }      
       log.error(eb);
       er.close();
       } catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
       	}
       }
   }
   
   private static String userExist(String name, String token){
       log.trace("Variables in : " + name + " " + token + " userExist");
	   String key_admin_url = "http://icp-icocs01.icp.ibm.com:5000/v3/users";
	   try{
		   URL url = new URL(key_admin_url);
		   HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	       connection.setUseCaches(false);
	       connection.setRequestMethod("GET");	
	       connection.setInstanceFollowRedirects(true);
	       connection.setRequestProperty("Content-Type","application/json");
	       connection.setRequestProperty("X-Auth-Token",token);
	       connection.setRequestProperty("name",name);
	       	       
	       checkForErrors(connection);
	
	       connection.disconnect();
	       
	       InputStream is = connection.getInputStream();
	       InputStreamReader isr = new InputStreamReader(is);
	       BufferedReader reader = new BufferedReader(isr);
	       String lines;
	       JSONObject obj;
	       StringBuffer sb = new StringBuffer("");
	       
	       while ((lines = reader.readLine()) != null) {
	    	   
	    	   lines = new String(lines.getBytes(), "utf-8");
	           obj = new JSONObject(lines);
	           sb.append(lines);
	//           System.out.println("USER "  + " /n" +obj.getJSONArray("users"));
	           name = name.substring(3, name.indexOf(","));
	           System.out.println(name);
	           JSONArray users = obj.getJSONArray("users");
	           
	           for ( int i=0 ; i < users.length(); i++){        	 
	        	   if(users.getJSONObject(i).getString("name").equals(name)){
	        		   log.trace("Index : " + i + " Name" + name + " ID" + users.getJSONObject(i).getString("id"));
	        		   return users.getJSONObject(i).getString("id");
	        	   }
	           }
	           return null;
	           }	
	   } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	   } catch (JSONException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}	      
	           return null;	  	   
   }
   
   private static String createUser(JSONObject user, String token) throws JSONException{
	   String key_admin_url = "http://icp-icocs01.icp.ibm.com:5000/v3/users";
	   try{
		   String ldi =  (String) user.get("LDIF");
		   ArrayList<String> ldif = new ArrayList<String>(Arrays.asList(ldi.split("\n")));
		   
	       String description = ldif.get(0).substring(ldif.get(0).indexOf(":")+1,ldif.get(0).length()-1) ; // Pull from user DN
	       String email = ldif.get(32).substring(ldif.get(32).indexOf(":")+1,ldif.get(32).length()-1) ; // Pull from user email
	       String name = ldif.get(5).substring(ldif.get(5).indexOf(":")+1,ldif.get(5).length()-1) ; // Pull from user name
	   		   
		   URL url = new URL(key_admin_url);
		   HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	       connection.setUseCaches(false);
	       connection.setRequestProperty("Content-Type","application/json");
	       connection.setRequestProperty("X-Auth-Token",token);
	       connection.setRequestMethod("POST");
	       
		   connection.setDoOutput(true);
	       connection.setDoInput(true);
	       connection.setInstanceFollowRedirects(true);	       	       
	       checkForErrors(connection);
	       
	       //TODO: Read default Project from properties file
	       String defaultProject = "53e0b60cfe1742de92475a410ed13f34";
	       
	       JSONObject json = new JSONObject();
	       JSONObject attrib = new JSONObject();
	       attrib.put("default_project_id",defaultProject);
	       attrib.put("description", description);
	       attrib.put("email", email);
	       attrib.put("enabled", true);
	       attrib.put("name",name);
	       json.put("user",attrib);
	       
	       log.trace("Full Request : " +json);
	       
	       OutputStream os =  connection.getOutputStream();
	       OutputStreamWriter out = new OutputStreamWriter(os);
	     			out.write(json.toString());
	                out.flush();
	                out.close();       
	       
	       checkForErrors(connection);

	
	       connection.disconnect();
	       
	       //connection getInputStream sends the PUT command.
	       InputStream is = connection.getInputStream();
	       InputStreamReader isr = new InputStreamReader(is);
	       BufferedReader reader = new BufferedReader(isr);
	       
	       String dn = ldif.get(8).substring(ldif.get(8).indexOf(":")+1,ldif.get(8).length()-1);

	       return dn;
	       //return reader.readLine();
	       
	       // That might not work, but should
	       
	       	       	
	       } catch (ProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	   
	   
	   
	   
	   
	   return "";
   }

   private static Boolean userInGroup(String name, String groupLink, String token){
	   String key_admin_url = groupLink + "/users";
	   try{
		   URL url = new URL(key_admin_url);
		   HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	       connection.setUseCaches(false);
	       connection.setRequestMethod("GET");	
	       connection.setInstanceFollowRedirects(true);
	       connection.setRequestProperty("Content-Type","application/json");
	       connection.setRequestProperty("X-Auth-Token",token);
	       connection.setRequestProperty("name",name);
	       	       
	       checkForErrors(connection);
	
	       connection.disconnect();
	       
	       InputStream is = connection.getInputStream();
	       InputStreamReader isr = new InputStreamReader(is);
	       BufferedReader reader = new BufferedReader(isr);
	       String lines;
	       JSONObject obj;
	       StringBuffer sb = new StringBuffer("");
	       
	       while ((lines = reader.readLine()) != null) {
		   
	    	   lines = new String(lines.getBytes(), "utf-8");
	           obj = new JSONObject(lines);
	           sb.append(lines);
	//           System.out.println("USER "  + " /n" +obj.getJSONArray("users"));
	           name = name.substring(3, name.indexOf(","));
	           JSONArray users = obj.getJSONArray("users");
                    
	           for ( int i=0 ; i < users.length(); i++){        	 

	        	   if(users.getJSONObject(i).getString("name").equals(name)){
	        		   log.trace("Index : " + i + " Name" + name + " ID" + users.getJSONObject(i).getString("id"));
	        		   return true;
	        	   }
	           }
	           return false;
	           }	
	   } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	   } catch (JSONException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}	      
	           return false;	  	   
   }
   
   private static void addUserToGroup(String userLink, String groupLink, String token) throws JSONException{
	   String key_admin_url = groupLink + "/users/" + userLink;
	   try{
		   log.trace("Values Passed : " + userLink +  " " + groupLink + " " + token);
		   URL url = new URL(key_admin_url);
		   HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	       connection.setUseCaches(false);
	       connection.setRequestProperty("Content-Type","application/json");
	       connection.setRequestProperty("X-Auth-Token",token);
	       connection.setRequestMethod("PUT");
	
	       connection.setInstanceFollowRedirects(true);	       	       
	       checkForErrors(connection);
	
	       System.out.println(connection.getResponseCode());
	       
	       connection.disconnect();
	       
	       System.out.println(connection.getResponseCode());
	       
	       //connection getInputStream sends the PUT command.
	       InputStream is = connection.getInputStream();
	       
	       return;		
	       } catch (ProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

   }

   //IGNORE getGroupMembers work in progress 
   private static JSONObject getGroupMembers(String projectName, String token) throws IOException, JSONException{
	   String key_admin_url = "http://icp-icocs01.icp.ibm.com:5000/v3/groups";
	   String response = null;
//	   try{
		   URL url = new URL(key_admin_url);
		   HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	       connection.setUseCaches(false);
	       connection.setRequestMethod("GET");	
	       connection.setInstanceFollowRedirects(true);
	       connection.setRequestProperty("Content-Type","application/json");
	       connection.setRequestProperty("X-Auth-Token",token);
	       
	       checkForErrors(connection);
	
	       connection.disconnect();
	       
	       InputStream is = connection.getInputStream();
	       InputStreamReader isr = new InputStreamReader(is);
	       BufferedReader reader = new BufferedReader(isr);
	       String lines;
	       JSONObject obj;
	       StringBuffer sb = new StringBuffer("");
	   
	       while ((lines = reader.readLine()) != null) {
	    	   
	    	   lines = new String(lines.getBytes(), "utf-8");
	           obj = new JSONObject(lines);
	           sb.append(lines);
	           System.out.println("/n/nOBJECT looks liks : " + obj.toString());
        	   System.out.println("/n/nUSER " + " /n" +obj.getJSONArray("users"));
	             
	           for(int i =0; i < obj.getJSONArray("users").length(); i++){
	        	   System.out.println("USER " + i + " /n" +obj.getJSONArray("users"));
	           }
	       }
	       
	     //  System.out.println("MEMBERS ARE : "+sb.toString());
	       
         

	       
	       
	       return new JSONObject();
	           
	   
   }
    
   private static String getGroupId(String groupName, String token){
	   // Searches Keystone for a project id corresponding to the projectName
	   // Working
	   // TODO: Separate into two calls 1:get JSONObject of groups 2:get Project by ID

	   String key_admin_url = "http://icp-icocs01.icp.ibm.com:5000/v3/groups";
	   String response = null;
	   try{
		   URL url = new URL(key_admin_url);
		   HttpURLConnection connection = (HttpURLConnection) url.openConnection();
	       connection.setUseCaches(false);
	       connection.setRequestMethod("GET");	
	       connection.setInstanceFollowRedirects(true);
	       connection.setRequestProperty("Content-Type","application/json");
	       connection.setRequestProperty("X-Auth-Token",token);
	       
	       checkForErrors(connection);
	
	       connection.disconnect();
	       
	       InputStream is = connection.getInputStream();
	       InputStreamReader isr = new InputStreamReader(is);
	       BufferedReader reader = new BufferedReader(isr);
	       String lines;
	       JSONObject obj;
	       StringBuffer sb = new StringBuffer("");
	       
	       while ((lines = reader.readLine()) != null) {
	    	   
	    	   lines = new String(lines.getBytes(), "utf-8");
	           obj = new JSONObject(lines);
	           sb.append(lines);
	           
	           for(int i =0; i < obj.getJSONArray("groups").length(); i++){
		           JSONObject temp = obj.getJSONArray("groups").getJSONObject(i);
		           String name = temp.getString("name");
		           String self = temp.getJSONObject("links").getString("self");
		           log.trace("Name "+name+" self "+self);
		           log.trace("Do these look similar? "+name+" & "+groupName);		           
		           if(name.equals(groupName)){
		        	   return self;
		           }
	           }
	       }   	             
	       log.trace(sb.toString());       		
	       return response;
	       
	   } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
	   } catch (JSONException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return "";
	   
   }
	
   private static String getToken() {
	   // Queries Keystone for an Admin Token, returns the Token as a String 
	   // Working
	   String key_admin_url = "http://icp-icocs01.icp.ibm.com:5000/v3/auth/tokens";
	   try{
	   URL url = new URL(key_admin_url);
	   HttpURLConnection connection = (HttpURLConnection) url
               .openConnection();
       
	   log.trace("Received a : " + connection.getClass().getName());
       
	   connection.setDoOutput(true);
       connection.setDoInput(true);
       connection.setUseCaches(false);
       connection.setRequestMethod("POST");

       connection.setInstanceFollowRedirects(true);
       connection.setRequestProperty("Content-Type","application/json");

       checkForErrors(connection);
              
       String jsonRequest = "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"domain\":{\"id\":\"default\"},\"password\":\"passw0rd\"}}}}}";
       
       OutputStream os =  connection.getOutputStream();
       OutputStreamWriter out = new OutputStreamWriter(os);
     			out.write(jsonRequest);
                out.flush();
                out.close();       
       
       checkForErrors(connection);

       connection.disconnect();
       return connection.getHeaderField(1);	   
   } catch (MalformedURLException e) {
       // TODO Auto-generated catch block
       e.printStackTrace();
   } catch (UnsupportedEncodingException e) {
       // TODO Auto-generated catch block
       e.printStackTrace();
   } catch (IOException e) {
       // TODO Auto-generated catch block
       e.printStackTrace();
   }
	  	return "";	 
	
}}
	
class Attribute<T, U> {
	//Class used to hold String representing the Group Name and Array of Strings holding Members
	//TODO: Implement better Data holder for members to retain email etc.
		public final T t;
		public final U u;	
		
	    public Attribute(T t, U u) {         
	        this.t= t;
	        this.u= u;
	        }
	    public String toString(){
	    	return this.t + ":" + Arrays.toString((String[]) this.u);
	    }
}
