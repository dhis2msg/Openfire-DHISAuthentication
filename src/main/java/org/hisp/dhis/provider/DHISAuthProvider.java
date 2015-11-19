package org.hisp.dhis.provider;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.*;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import net.iharder.Base64;
import org.apache.commons.httpclient.auth.AuthenticationException;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.group.*;
import org.jivesoftware.openfire.user.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;



/**
 * @author Niclas Halvorsen & Simon Nguyen Pettersen
 */


public class DHISAuthProvider implements AuthProvider {
	private static final Logger Log = LoggerFactory.getLogger(DHISAuthProvider.class);
	
	String nickname = "";
    String dhisId = "";
    
    private String DhisURL =  "https://hmis.moh.gov.rw/hmis/api/me"; //"https://" + XMPPServer.getInstance().getServerInfo().getXMPPDomain() + "/hmis/api/me";
    private String GROUP_NAME = "hmis-rwanda"; 
    private String GROUP_DESCRIPTION = "Group for the hmis in Rwanda";
    private String DOMAIN = "hmis.rwanda";
    
    /*public DHISAuthProvider() {
         DhisURL = org.jivesoftware.util.LocaleUtils.getLocalizedString("dhis.server", "dhis_provider");
         GROUP_NAME = org.jivesoftware.util.LocaleUtils.getLocalizedString("dhis.group", "dhis_provider");
         GROUP_DESCRIPTION = org.jivesoftware.util.LocaleUtils.getLocalizedString("dhis.group.description", "dhis_provider");
         DOMAIN = org.jivesoftware.util.LocaleUtils.getLocalizedString("dhis.domain", "dhis_provider");
    }*/

    public void authenticate(String username, String password) throws UnauthorizedException {
        if (username == null || password == null) {
            throw new UnauthorizedException();
        }

        if (username.contains("@")) {
            int index = username.indexOf("@");
            username = username.substring(0, index);
        } 
         
        if(!loginToDhis(username,password)){
            throw new UnauthorizedException();
        }

        UserManager userManager= UserManager.getInstance();
        User user = null;
        try {
            user = userManager.getUser(username);
        }
        catch (UserNotFoundException unfe) {
        	String email = username + "@" + DOMAIN;
            try {
                UserManager.getInstance().getUserProvider().createUser(username, password, nickname, null );
                if(user == null){
                    Log.debug("Something went wrong in DHISUserProvider");
                    throw new UnauthorizedException();
                }
            }catch (UserAlreadyExistsException uaee) {}
        }

        if (user != null) {
            addUserToGroup(username);
        }
        else {
        	Log.debug("User was not found, and could not be created..");
        }
    }

    public void addUserToGroup(String username) {
        GroupManager groupManager = GroupManager.getInstance();
        if(groupManager == null) {Log.debug("Groupmanger == null: ");}
        else{
            JID jid = new JID(username+"@"+ XMPPServer.getInstance().getServerInfo().getXMPPDomain()  );
            GroupProvider provider = groupManager.getProvider();
            if(provider == null)
                Log.debug("GroupProvider = null: ");

            Group group = null;

            try{
                Log.debug("Trying to get group " + GROUP_NAME);
                group = groupManager.getGroup(GROUP_NAME);
            }catch(GroupNotFoundException e){
            	try {
            		group = groupManager.createGroup(GROUP_NAME);
                    group.setDescription(GROUP_DESCRIPTION);
                    Log.debug("Group: " + group.getName() + " created");
                 } 
            	catch (GroupAlreadyExistsException ge) {}
            }catch(Exception e){}
            finally{
            	if(group != null){
            		if (group.isUser(username)) {
            			Log.debug("Allready a member: " + username);
            		}
                    else {
                    	Log.debug("Adding user to group");
                    	try {
                            groupManager.getProvider().addMember(group.getName(), jid, false);
                    	} catch (UnsupportedOperationException e) {
                        Log.debug("UnsupportedOperationException");
                    	}
                    }
            	}
            }
        }
    }

    public boolean loginToDhis(String username, String password){
    	Log.debug("Trying to login to dhis..");
        //String formatCredentials = String.format("%s:%s", username, password);
        //String bytesEncoded = Base64.encodeBytes(formatCredentials.getBytes());      
        String authStr = username + ":" + password;
        String authEncoded = Base64.encodeBytes(authStr.getBytes());
        int code = -1;
        String body = "";
     
        acceptHost();
        HttpsURLConnection connection = null;
        try {
            URL url = new URL(DhisURL);
            connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestProperty("Authorization", "Basic " + authEncoded);
            connection.setRequestProperty("Accept","application/json");
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(1500);
            connection.setInstanceFollowRedirects(false);
            connection.setDoInput(true);
            connection.connect();

            code = connection.getResponseCode();
            body = readInputStream(connection.getInputStream());
        }
        catch (SocketTimeoutException e) {

            e.printStackTrace();
            return false;
        }
        catch (MalformedURLException e) {

            e.printStackTrace();
            return false;
        }catch(AuthenticationException e){
     
        	e.printStackTrace();
        	return false;
        	
        }
        catch (IOException one) {

        	return false;
        }catch (Exception e){
        
        	return false;
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        return true;
    }
    private String setUsername(String body){
        try {
            JSONObject json = new JSONObject(body);
            nickname = json.getString("firstName") + " " + json.getString("surname");
        }catch(JSONException  e){
            nickname = "NoNickname";
        }
        return nickname;
    }

    private String readInputStream(InputStream stream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
        StringBuilder builder = new StringBuilder();
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line);
                builder.append('\n');
            }
            reader.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return builder.toString();
    }

    public void authenticate(String username, String token, String digest) throws UnauthorizedException
    {
        throw new UnauthorizedException("Digest authentication not supported.");
    }

    private static void acceptHost() {
        try
        {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                }

                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                }

                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }

    /*
     * Non modified required AuthProvider methods
     */
    public boolean isPlainSupported() {
        return true;
    }

    public boolean isDigestSupported() {
        return false;
    }

    public String getPassword(String username)
            throws UserNotFoundException, UnsupportedOperationException
    {
        throw new UnsupportedOperationException();
    }

     public void setPassword(String username, String password) throws UserNotFoundException {
        throw new UnsupportedOperationException();
    }

    public boolean supportsPasswordRetrieval() {
        return false;
    }
}