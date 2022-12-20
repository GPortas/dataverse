package edu.harvard.iq.dataverse.api;

import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.AuthenticationServiceBean;
import edu.harvard.iq.dataverse.authorization.exceptions.AuthenticationFailedException;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider;

import javax.annotation.Priority;
import javax.ejb.EJB;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class SecurityFilter implements ContainerRequestFilter {

    @EJB
    protected AuthenticationServiceBean authSvc;

    // TODO: More descriptive responses
    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {
        // Cascade filtering of auth mechanisms goes here
        // Testing HTTP Basic Authentication for this PoC
        String authHeader = containerRequestContext.getHeaderString("Authorization");
        if (authHeader == null || !authHeader.startsWith("Basic")) {
            containerRequestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            return;
        }

        AuthenticationRequest authReq = new AuthenticationRequest();
        try {
            String[] tokens = (new String(Base64.getDecoder().decode(authHeader.split(" ")[1]), StandardCharsets.UTF_8)).split(":");
            authReq.putCredential(BuiltinAuthenticationProvider.KEY_USERNAME_OR_EMAIL, tokens[0]);
            authReq.putCredential(BuiltinAuthenticationProvider.KEY_PASSWORD, tokens[1]);
        } catch (Exception e) {
            containerRequestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            return;
        }

        try {
            authSvc.getUpdateAuthenticatedUser(BuiltinAuthenticationProvider.PROVIDER_ID, authReq);
        } catch (AuthenticationFailedException ex) {
            containerRequestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }
}
