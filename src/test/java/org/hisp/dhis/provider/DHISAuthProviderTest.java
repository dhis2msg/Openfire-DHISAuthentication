package org.hisp.dhis.provider;

import net.iharder.Base64;
import org.assertj.core.api.Assertions;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.net.URL;

public class DHISAuthProviderTest {

    private static final String DHIS_SERVER_URL = System.getProperty("dhis.server.url", "http://localhost:8082");

    private static final String USERNAME = "admin";
    private static final String PASSWORD = "district";

    private static final String TOKEN = "token";
    private static final String DIGEST = "digest";

    private static final String NOT_EXISTING_USERNAME = "john";
    private static final String WRONG_PASSWORD = "password";

    private DHISAuthProvider dhisAuthProvider;

    @Before
    public void setUp() throws Exception {
        dhisAuthProvider = new DHISAuthProvider(DHIS_SERVER_URL);
    }

    @After
    public void tearDown() throws Exception {
        dhisAuthProvider = null;
    }

    private boolean isDHISServerRunning() {
        String authStr = USERNAME + ":" + PASSWORD;
        String authEncoded = Base64.encodeBytes(authStr.getBytes());

        try {
            URL url = new URL(DHIS_SERVER_URL + "/api/me");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty("Authorization", "Basic " + authEncoded);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(1500);
            connection.setInstanceFollowRedirects(true);
            connection.setDoInput(true);
            connection.connect();
            return connection.getResponseCode() == 200;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    @Test
    public void testAuthenticate() throws Exception {
        Assume.assumeTrue(isDHISServerRunning());
        dhisAuthProvider.authenticate(USERNAME, PASSWORD);
    }

    @Test(expected = UnauthorizedException.class)
    public void testAuthenticateNullUsername() throws Exception {
        dhisAuthProvider.authenticate(null, PASSWORD);
    }

    @Test(expected = UnauthorizedException.class)
    public void testAuthenticateNotExistingUsername() throws Exception {
        Assume.assumeTrue(isDHISServerRunning());
        dhisAuthProvider.authenticate(NOT_EXISTING_USERNAME, PASSWORD);
    }

    @Test(expected = UnauthorizedException.class)
    public void testAuthenticateNullPassword() throws Exception {
        dhisAuthProvider.authenticate(USERNAME, null);
    }

    @Test(expected = UnauthorizedException.class)
    public void testAuthenticateWrongPassword() throws Exception {
        Assume.assumeTrue(isDHISServerRunning());
        dhisAuthProvider.authenticate(USERNAME, WRONG_PASSWORD);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testAuthenticateWithDigest() throws Exception {
        dhisAuthProvider.authenticate(USERNAME, TOKEN, DIGEST);
    }

    @Test
    public void testIsPlainSupported() throws Exception {
        Assertions.assertThat(dhisAuthProvider.isPlainSupported()).isTrue();
    }

    @Test
    public void testIsDigestSupported() throws Exception {
        Assertions.assertThat(dhisAuthProvider.isDigestSupported()).isFalse();
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetPassword() throws Exception {
        dhisAuthProvider.getPassword(USERNAME);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testSetPassword() throws Exception {
        dhisAuthProvider.setPassword(USERNAME, PASSWORD);
    }

    @Test
    public void testSupportsPasswordRetrieval() throws Exception {
        Assertions.assertThat(dhisAuthProvider.supportsPasswordRetrieval()).isFalse();
    }

}
