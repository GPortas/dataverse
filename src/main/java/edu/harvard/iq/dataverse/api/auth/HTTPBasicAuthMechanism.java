package edu.harvard.iq.dataverse.api.auth;

import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.AuthenticationServiceBean;
import edu.harvard.iq.dataverse.authorization.exceptions.AuthenticationFailedException;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;

import javax.ejb.EJB;
import javax.ws.rs.container.ContainerRequestContext;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class HTTPBasicAuthMechanism extends AuthMechanism {

    @EJB
    AuthenticationServiceBean authSvc;

    private static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    private static final String AUTHORIZATION_HEADER_PREFIX = "Basic";

    // TODO: More descriptive exceptions
    @Override
    public AuthenticatedUser getAuthenticatedUserFromRequest(ContainerRequestContext containerRequestContext) throws AuthException {
        String authHeader = containerRequestContext.getHeaderString(AUTHORIZATION_HEADER_NAME);
        if (authHeader == null || !authHeader.startsWith(AUTHORIZATION_HEADER_PREFIX)) {
            throw new AuthException();
        }

        AuthenticationRequest authReq = new AuthenticationRequest();
        try {
            String[] tokens = (new String(Base64.getDecoder().decode(authHeader.split(" ")[1]), StandardCharsets.UTF_8)).split(":");
            authReq.putCredential(BuiltinAuthenticationProvider.KEY_USERNAME_OR_EMAIL, tokens[0]);
            authReq.putCredential(BuiltinAuthenticationProvider.KEY_PASSWORD, tokens[1]);
        } catch (Exception e) {
            throw new AuthException();
        }

        try {
            return authSvc.getUpdateAuthenticatedUser(BuiltinAuthenticationProvider.PROVIDER_ID, authReq);
        } catch (AuthenticationFailedException ex) {
            throw new AuthException();
        }
    }
}
