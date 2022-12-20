package edu.harvard.iq.dataverse.api.auth;

import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;

import javax.ws.rs.container.ContainerRequestContext;

public interface AuthMechanism {

    public AuthenticatedUser authenticateRequest(ContainerRequestContext containerRequestContext) throws AuthException;
}
