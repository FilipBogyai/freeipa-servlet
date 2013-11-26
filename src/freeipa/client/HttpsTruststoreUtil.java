package freeipa.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.apache.commons.io.IOUtils;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;

public class HttpsTruststoreUtil {

    public static DefaultHttpClient getHttpClientWithSSL(File trustStoreFile, String password) {
        return getHttpClientWithSSL(null, null, trustStoreFile, password);
    }

    public static DefaultHttpClient getHttpClientWithSSL(File keyStoreFile, String keyStorePassword, File trustStoreFile,
            String trustStorePassword) {

        try {
            final KeyStore truststore = loadKeyStore(trustStoreFile, trustStorePassword.toCharArray());
            final KeyStore keystore = keyStoreFile != null ? loadKeyStore(keyStoreFile, keyStorePassword.toCharArray()) : null;
            final SSLSocketFactory ssf = new SSLSocketFactory(SSLSocketFactory.TLS, keystore, keyStorePassword, truststore, null,
                    SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            HttpParams params = new BasicHttpParams();

            SchemeRegistry registry = new SchemeRegistry();
            registry.register(new Scheme("http", 80, PlainSocketFactory.getSocketFactory()));
            registry.register(new Scheme("https", 443, ssf));
            ClientConnectionManager ccm = new PoolingClientConnectionManager(registry);
            return new DefaultHttpClient(ccm, params);
        } catch (Exception e) {

            return new DefaultHttpClient();
        }
    }

    /**
     * Loads a JKS keystore with given path and password.
     * 
     * @param keystoreFile
     *            path to keystore file
     * @param keystorePwd
     *            keystore password
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    private static KeyStore loadKeyStore(final File keystoreFile, final char[] keystorePwd) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        final KeyStore keystore = KeyStore.getInstance("JKS");
        InputStream is = null;
        try {
            is = new FileInputStream(keystoreFile);
            keystore.load(is, keystorePwd);
        } finally {
            IOUtils.closeQuietly(is);
        }
        return keystore;
    }

}
