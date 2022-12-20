package edu.harvard.iq.dataverse.api.auth;

import edu.harvard.iq.dataverse.DataverseSession;
import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;

abstract class AuthMechanism {

    @Inject
    DataverseSession session;

    public void authenticateRequest(ContainerRequestContext containerRequestContext) throws AuthException {
        AuthenticatedUser authenticatedUser = getAuthenticatedUserFromRequest(containerRequestContext);
        session.setUser(authenticatedUser);
    }

    abstract AuthenticatedUser getAuthenticatedUserFromRequest(ContainerRequestContext containerRequestContext) throws AuthException;
}
