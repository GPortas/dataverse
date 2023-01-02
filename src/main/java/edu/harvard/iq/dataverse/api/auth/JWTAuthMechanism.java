package edu.harvard.iq.dataverse.api.auth;

import com.auth0.jwt.interfaces.DecodedJWT;
import edu.harvard.iq.dataverse.UserServiceBean;
import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;

import javax.ejb.EJB;
import javax.ws.rs.container.ContainerRequestContext;
import java.util.logging.Logger;

import static edu.harvard.iq.dataverse.api.JWTUtil.verifyJWTToken;

public class JWTAuthMechanism extends AuthMechanism {

    private static final Logger logger = Logger.getLogger(JWTAuthMechanism.class.getCanonicalName());

    @EJB
    UserServiceBean userService;

    private static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    private static final String AUTHORIZATION_HEADER_PREFIX = "Bearer";

    // TODO: More descriptive exceptions
    @Override
    public AuthenticatedUser getAuthenticatedUserFromRequest(ContainerRequestContext containerRequestContext) throws AuthException {
        String authHeader = containerRequestContext.getHeaderString(AUTHORIZATION_HEADER_NAME);
        if (authHeader == null || !authHeader.startsWith(AUTHORIZATION_HEADER_PREFIX)) {
            throw new AuthException();
        }
        try {
            String jwtToken = authHeader.substring(7);
            logger.info("Received JWT: " + jwtToken);
            DecodedJWT decodedJWT = verifyJWTToken(jwtToken);
            long userId = Long.parseLong(decodedJWT.getSubject());
            return userService.find(userId);
        } catch (Exception e) {
            logger.info("Exception thrown while verifying JWT " + e.getMessage());
            throw new AuthException();
        }
    }
}
