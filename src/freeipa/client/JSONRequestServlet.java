/*
 * JBoss, Home of Professional Open Source.
 * 
 * Copyright 2007, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package freeipa.client;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.log4j.Logger;

/**
 * A servlet to test json API of Free IPA
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
@WebServlet(name = "JSONRequestServlet", urlPatterns = { "/post/" }, loadOnStartup = 1)
public class JSONRequestServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(JSONRequestServlet.class);
    private static final String SECURITY_DOMAIN = "host";
    private static final File TRUSTSTORE_FILE = new File("/home/fbogyai/development/freeipa-client-resources/dhcp-4-114.jks");
    private static final String TRUSTSTORE_PASS = "secret";
    private static final DefaultHttpClient httpClient = HttpsTruststoreUtil
            .getHttpClientWithSSL(TRUSTSTORE_FILE, TRUSTSTORE_PASS);

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        String jsonRequest = req.getParameter("json");
        URL ipaUrl = new URL("https://vm-144.idm.lab.eng.brq.redhat.com/ipa/json");
        PrintWriter writer = resp.getWriter();

        writer.println("<html>");
        writer.println("  <head>");
        writer.println("    <title>Json request servlet</title>");
        writer.println("  </head>");
        writer.println("  <body>");
        writer.println("    <h1>JSON POST Test:</h1>");

        displayForm(writer);
        if (jsonRequest == null) {
            try {
                LoginContext context = new LoginContext(SECURITY_DOMAIN);
                log.debug("Obtained LoginContext for '" + SECURITY_DOMAIN + "' security-domain.");

                context.login();
                writer.println("<h4>Authenticated</h4>");

                Subject subject = context.getSubject();
                KerberosHttpClient.makeCallWithKerberosAuthn(ipaUrl, subject, httpClient);
            } catch (Exception e) {
                // TODO - Output full exception detail.
                writer.println("<h5>Failed!</h5>");
                writer.print("<p>");
                writer.print(e.getClass().getName());
                writer.print(" - ");
                writer.print(e.getMessage());
                writer.println("</p>");

                log.error("testDomain Failed", e);
            }
        } else {
            testRequest(jsonRequest, writer);
        }

        writer.println("  </body>");
        writer.println("</html>");
        writer.flush();
    }

    private void displayForm(final PrintWriter writer) {
        writer.println("    <p>Please enter request you wish to make on FreeIPA.</p>");
        writer.println("    <p>");
        writer.println("      <form method='get'>");
        writer.println("        Security Domain <input type='text' name='json' value='{\"method\":\"cert_show\",\"params\":[[\"1\"],{}]}'><br>");
        writer.println("        <br><input type='submit' value='Test'>");
        writer.println("      </form>");
        writer.println("    </p>");
    }

    private void testRequest(final String jsonRequest, final PrintWriter writer) {

        writer.print(jsonRequest);
        writer.println("'</p>");
        URL ipaUrl;
        byte[] token = new byte[0];
        Subject subject = new Subject();
        try {
            ipaUrl = new URL("https://vm-144.idm.lab.eng.brq.redhat.com/ipa/json");

            KerberosHttpClient ipaClient = new KerberosHttpClient(token, subject);
            String response = ipaClient.makeRequest(ipaUrl, httpClient, jsonRequest);
            writer.println(response);
        } catch (Exception e) {
            writer.println("<h5>Failed!</h5>");
            writer.print("<p>");
            writer.print(e.getClass().getName());
            writer.print(" - ");
            writer.print(e.getMessage());
            writer.println("</p>");

            log.error("testDomain Failed", e);
        }

    }

    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        // Handle POST the same as GET.
        doGet(req, resp);
    }

}
