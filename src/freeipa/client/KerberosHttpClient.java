package freeipa.client;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.AuthPolicy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.NegotiateSchemeFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import freeipa.client.negotiation.JBossNegotiateSchemeFactory;
import freeipa.client.negotiation.NullCredentials;

public class KerberosHttpClient {

    private static final String TRUSTSTORE_FILE = "/home/fbogyai/development/freeipa-client-resources/dhcp-4-114.jks";
    private final byte[] spnegoToken;
    private final Subject subject;

    public KerberosHttpClient(byte[] token, Subject subject) {
        this.spnegoToken = token;
        this.subject = subject;
    }

    public String certificateRequest(URL url) {

        String responseString = null;

        File trustore = new File(TRUSTSTORE_FILE);
        DefaultHttpClient httpClient = HttpsTruststoreUtil.getHttpClientWithSSL(trustore, "secret", trustore, "secret");
        try {

            responseString = makeCallWithKerberosAuthn(url, subject, httpClient);
            System.out.println(responseString);
            System.out.println("druhy pokus");
            // responseString += makeCall(url, httpClient);
            // System.out.println(responseString);

        } catch (Exception ex) {
            ex.printStackTrace();

        } finally {
            httpClient.getConnectionManager().shutdown();
        }

        return responseString;

    }

    /**
     * Requests given URL and checks if the returned HTTP status code is the
     * expected one. Returns HTTP response body
     * 
     * @param URL
     *            url to which the request should be made
     * @param DefaultHttpClient
     *            httpClient to test multiple access
     * @param expectedStatusCode
     *            expected status code returned from the requested server
     * @return HTTP response body
     * @throws ClientProtocolException
     * @throws IOException
     * @throws URISyntaxException
     */
    public String makeCall(URL url, DefaultHttpClient httpClient) throws ClientProtocolException,
            IOException, URISyntaxException {

        String httpResponseBody = null;
        HttpGet httpGet = new HttpGet(url.toURI());

        httpGet.addHeader("Referer", "https://vm-144.idm.lab.eng.brq.redhat.com/ipa/ui/");

        byte[] encodedBytes = org.apache.commons.codec.binary.Base64.encodeBase64(spnegoToken);
        String encoded = new String(encodedBytes);
        System.out.println(encoded);
        httpGet.addHeader("Authorization", "Negotiate " + encoded);

        HttpResponse response = httpClient.execute(httpGet);
        HttpEntity responseEntity = response.getEntity();

        Header headers[] = response.getAllHeaders();
        for (Header h : headers) {
            System.out.println(h.getName() + ": " + h.getValue());
        }

        if (responseEntity != null)
            httpResponseBody = EntityUtils.toString(response.getEntity());
        EntityUtils.consume(responseEntity);

        StatusLine statusLine = response.getStatusLine();
        System.out.println("Request to: " + url + " responds: " + statusLine);
        // Post authentication - we have a 302
        Header locationHeader = response.getFirstHeader("Location");
        if (locationHeader != null) {

            System.out.println(locationHeader.getValue());
        }
        return httpResponseBody;
    }

    /**
     * Makes HTTP post with JSON format
     * 
     * @param URL
     * @param DefaultHttpClient
     *            httpClient to test multiple access
     * @throws ClientProtocolException
     * @throws IOException
     * @throws URISyntaxException
     */

    public String makePost(URL url, DefaultHttpClient httpClient) throws ClientProtocolException, IOException, URISyntaxException {

        HttpPost httpost = new HttpPost(url.toURI());
        String httpResponseBody = null;

        NegotiateSchemeFactory nsf = new NegotiateSchemeFactory();
        httpClient.getAuthSchemes().register(AuthPolicy.SPNEGO, nsf);

        httpClient.getCredentialsProvider().setCredentials(new AuthScope(null, -1, null), new NullCredentials());

        httpost.addHeader("Content-Type", "application/json");
        httpost.addHeader("Referer", "https://vm-144.idm.lab.eng.brq.redhat.com/ipa/ui/");

        byte[] encodedBytes = org.apache.commons.codec.binary.Base64.encodeBase64(this.spnegoToken);
        String encoded = new String(encodedBytes);
        System.out.println(encoded);
        httpost.addHeader("Authorization", "Negotiate " + encoded);

        StringEntity entity = new StringEntity("{\"method\":\"cert_show\",\"params\":[[\"1\"],{}]}");
        httpost.setEntity(entity);

        HttpResponse response = httpClient.execute(httpost);
        HttpEntity responseEntity = response.getEntity();

        Header headers[] = response.getAllHeaders();
        for (Header h : headers) {
            System.out.println(h.getName() + ": " + h.getValue());
        }

        if (responseEntity != null)
            httpResponseBody = EntityUtils.toString(response.getEntity());
        EntityUtils.consume(responseEntity);

        StatusLine statusLine = response.getStatusLine();
        System.out.println("Request to: " + url + " responds: " + statusLine);
        // Post authentication - we have a 302
        Header locationHeader = response.getFirstHeader("Location");
        if (locationHeader != null) {

            System.out.println(locationHeader.getValue());
        }
        return httpResponseBody;

    }

    public String makeRequest(URL url, DefaultHttpClient httpClient, String request) throws URISyntaxException,
            ClientProtocolException, IOException {

        HttpPost httpost = new HttpPost(url.toURI());
        String httpResponseBody = null;

        StringEntity entity = new StringEntity(request);
        httpost.setEntity(entity);

        HttpResponse response = httpClient.execute(httpost);
        HttpEntity responseEntity = response.getEntity();

        if (responseEntity != null)
            httpResponseBody = EntityUtils.toString(response.getEntity());
        EntityUtils.consume(responseEntity);

        StatusLine statusLine = response.getStatusLine();
        System.out.println("Request to: " + url + " responds: " + statusLine);

        return httpResponseBody;
    }

    /**
     * Returns response body for the given URL request as a String. It also
     * checks if the returned HTTP status code is the expected one. If the
     * server returns {@link HttpServletResponse#SC_UNAUTHORIZED} and an
     * username is provided, then the given user is authenticated against
     * Kerberos and a new request is executed under the new subject.
     * 
     * @param url
     *            URI to which the request should be made
     * @param user
     *            Username
     * @param pass
     *            Password
     * @param expectedStatusCode
     *            expected status code returned from the requested server
     * @return HTTP response body
     * @throws IOException
     * @throws URISyntaxException
     * @throws PrivilegedActionException
     * @throws LoginException
     */
    public static String makeCallWithKerberosAuthn(final URL url, final Subject subject, final DefaultHttpClient httpClient)
            throws IOException, URISyntaxException,
            PrivilegedActionException, LoginException {

        try {
            httpClient.getAuthSchemes().register(AuthPolicy.SPNEGO, new JBossNegotiateSchemeFactory(true));
            httpClient.getCredentialsProvider().setCredentials(new AuthScope(null, -1, null), new NullCredentials());
            final HttpGet httpGet = new HttpGet(url.toURI());
            httpGet.addHeader("Referer", "https://vm-144.idm.lab.eng.brq.redhat.com/ipa/");

            /*
             * final HttpGet httpGet = new HttpGet(uri); final HttpResponse
             * response = httpClient.execute(httpGet); int statusCode =
             * response.getStatusLine().getStatusCode();
             * 
             * final HttpEntity entity = response.getEntity(); final Header[]
             * authnHeaders = response.getHeaders("WWW-Authenticate");
             * assertTrue("WWW-Authenticate header is present", authnHeaders !=
             * null && authnHeaders.length > 0); final Set<String>
             * authnHeaderValues = new HashSet<String>(); for (final Header
             * header : authnHeaders) {
             * authnHeaderValues.add(header.getValue()); }
             * assertTrue("WWW-Authenticate: Negotiate header is missing",
             * authnHeaderValues.contains("Negotiate"));
             * 
             * System.out.println(
             * "HTTP response was SC_UNAUTHORIZED, let's authenticate the user "
             * );
             * 
             * if (entity != null) EntityUtils.consume(entity);
             */
            // 2. Perform the work as authenticated Subject.
            final String responseBody = Subject.doAs(subject, new PrivilegedExceptionAction<String>() {
                public String run() throws Exception {
                    final HttpResponse response = httpClient.execute(httpGet);
                    int statusCode = response.getStatusLine().getStatusCode();
                    System.out.println("Unexpected status code returned after the authentication." + statusCode);
                    return EntityUtils.toString(response.getEntity());
                }
            });

            return responseBody;
        } finally {

        }
    }


}
