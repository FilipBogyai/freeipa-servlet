package freeipa.client;

import java.security.Principal;
import java.security.PrivilegedExceptionAction;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

class SPNEGOTokenGeneratorAction implements PrivilegedExceptionAction<byte[]> {

    private final Principal spn;

    SPNEGOTokenGeneratorAction(Principal spn) {
        this.spn = spn;
    }

    public byte[] run() throws GSSException {
        Oid spnegoOid = new Oid("1.3.6.1.5.5.2");

        GSSManager manager = GSSManager.getInstance();

        GSSName gssServerName = manager.createName(this.spn.getName(), null);

        GSSContext context = manager.createContext(gssServerName.canonicalize(spnegoOid), spnegoOid, null, 0);

        return context.initSecContext(new byte[0], 0, 0);
    }
}