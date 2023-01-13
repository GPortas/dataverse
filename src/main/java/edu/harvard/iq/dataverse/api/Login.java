package edu.harvard.iq.dataverse.api;

import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.exceptions.AuthenticationFailedException;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;

import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.io.StringReader;

import static edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider.KEY_PASSWORD;
import static edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider.KEY_USERNAME_OR_EMAIL;

/**
 * Contains the API calls that allow user login
 *
 * @author GPortas
 */
@Stateless
@Path("login")
public class Login extends AbstractApiBean {

    @POST
    @Path("builtinLogin")
    @Produces("application/json")
    public Response builtinLogin(String jsonBody) {
        if (jsonBody == null || jsonBody.isEmpty()) {
            return error(Response.Status.BAD_REQUEST, "You must supply JSON to this API endpoint and it must contain the user login credentials.");
        }

        StringReader rdr = new StringReader(jsonBody);
        JsonObject json = Json.createReader(rdr).readObject();
        AuthenticationRequest authReq = new AuthenticationRequest();
        try {
            authReq.putCredential(KEY_USERNAME_OR_EMAIL, json.getString("username"));
            authReq.putCredential(KEY_PASSWORD, json.getString("password"));
        } catch (Exception e) {
            return error(Response.Status.BAD_REQUEST, "Invalid JSON supplied");
        }

        try {
            AuthenticatedUser authenticatedUser = authSvc.getUpdateAuthenticatedUser(BuiltinAuthenticationProvider.PROVIDER_ID, authReq);
            session.setUser(authenticatedUser);
            return ok("User logged in");
        } catch (AuthenticationFailedException ex) {
            return error(Response.Status.UNAUTHORIZED, "Invalid user credentials provided");
        }
    }
}
