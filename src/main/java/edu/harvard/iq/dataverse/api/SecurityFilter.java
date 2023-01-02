package edu.harvard.iq.dataverse.api;

import edu.harvard.iq.dataverse.api.auth.AuthException;
import edu.harvard.iq.dataverse.api.auth.JWTAuthMechanism;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class SecurityFilter implements ContainerRequestFilter {

    @Inject
    private JWTAuthMechanism jwtAuthMechanism;

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {
        // Cascade filtering of auth mechanisms goes here
        // Testing JWT Authentication for this PoC
        try {
            jwtAuthMechanism.authenticateRequest(containerRequestContext);
        } catch (AuthException e) {
            containerRequestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }
}
