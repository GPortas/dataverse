/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.harvard.iq.dataverse.api;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import edu.harvard.iq.dataverse.authorization.AuthenticationRequest;
import edu.harvard.iq.dataverse.authorization.exceptions.AuthenticationFailedException;
import edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.users.ApiToken;
import edu.harvard.iq.dataverse.authorization.users.AuthenticatedUser;
import edu.harvard.iq.dataverse.authorization.users.User;
import edu.harvard.iq.dataverse.engine.command.impl.ChangeUserIdentifierCommand;
import edu.harvard.iq.dataverse.engine.command.impl.GetUserTracesCommand;
import edu.harvard.iq.dataverse.engine.command.impl.MergeInAccountCommand;
import edu.harvard.iq.dataverse.engine.command.impl.RevokeAllRolesCommand;
import edu.harvard.iq.dataverse.util.FileUtil;
import org.apache.commons.lang.RandomStringUtils;

import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.io.StringReader;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider.KEY_PASSWORD;
import static edu.harvard.iq.dataverse.authorization.providers.builtin.BuiltinAuthenticationProvider.KEY_USERNAME_OR_EMAIL;
import static edu.harvard.iq.dataverse.util.json.JsonPrinter.json;

/**
 *
 * @author madunlap
 */
@Stateless
@Path("users")
public class Users extends AbstractApiBean {

    private static final int CSRF_TOKEN_LENGTH = 20;
    public static final String CSRF_TOKEN_HEADER_NAME = "X-CSRF-Token";

    @POST
    @Path("{consumedIdentifier}/mergeIntoUser/{baseIdentifier}")
    public Response mergeInAuthenticatedUser(@PathParam("consumedIdentifier") String consumedIdentifier, @PathParam("baseIdentifier") String baseIdentifier) {
        User u;
        try {
            u = findUserOrDie();
            if(!u.isSuperuser()) {
                throw new WrappedResponse(error(Response.Status.UNAUTHORIZED, "Only superusers can merge users"));
            }
        } catch (WrappedResponse ex) {
            return ex.getResponse();
        }
        
        if(null == baseIdentifier || baseIdentifier.isEmpty()) {
            return error(Response.Status.BAD_REQUEST, "Base identifier provided to change is empty.");
        } else if(null == consumedIdentifier || consumedIdentifier.isEmpty()) {
            return error(Response.Status.BAD_REQUEST, "Identifier to merge in is empty.");
        }

        AuthenticatedUser baseAuthenticatedUser = authSvc.getAuthenticatedUser(baseIdentifier);
        if (baseAuthenticatedUser == null) {
            return error(Response.Status.BAD_REQUEST, "User " + baseIdentifier + " not found in AuthenticatedUser");
        }

        AuthenticatedUser consumedAuthenticatedUser = authSvc.getAuthenticatedUser(consumedIdentifier);
        if (consumedAuthenticatedUser == null) {
            return error(Response.Status.BAD_REQUEST, "User " + consumedIdentifier + " not found in AuthenticatedUser");
        }

        try {
            execCommand(new MergeInAccountCommand(createDataverseRequest(u), consumedAuthenticatedUser,  baseAuthenticatedUser));
        } catch (Exception e){
            return error(Response.Status.BAD_REQUEST, "Error calling ChangeUserIdentifierCommand: " + e.getLocalizedMessage());
        }

        return ok(String.format("All account data for %s has been merged into %s.", consumedIdentifier, baseIdentifier));
    }

    @POST
    @Path("{identifier}/changeIdentifier/{newIdentifier}")
    public Response changeAuthenticatedUserIdentifier(@PathParam("identifier") String oldIdentifier, @PathParam("newIdentifier")  String newIdentifier) {
        User u;
        try {
            u = findUserOrDie();
            if(!u.isSuperuser()) {
                throw new WrappedResponse(error(Response.Status.UNAUTHORIZED, "Only superusers can change userIdentifiers"));
            }
        } catch (WrappedResponse ex) {
            return ex.getResponse();
        }
        
        if(null == oldIdentifier || oldIdentifier.isEmpty()) {
            return error(Response.Status.BAD_REQUEST, "Old identifier provided to change is empty.");
        } else if(null == newIdentifier || newIdentifier.isEmpty()) {
            return error(Response.Status.BAD_REQUEST, "New identifier provided to change is empty.");
        }

        AuthenticatedUser authenticatedUser = authSvc.getAuthenticatedUser(oldIdentifier);
        if (authenticatedUser == null) {
            return error(Response.Status.BAD_REQUEST, "User " + oldIdentifier + " not found in AuthenticatedUser");
        }

        try {
            execCommand(new ChangeUserIdentifierCommand(createDataverseRequest(u), authenticatedUser,  newIdentifier));
        } catch (Exception e){
            return error(Response.Status.BAD_REQUEST, "Error calling ChangeUserIdentifierCommand: " + e.getLocalizedMessage());
        }

        return ok("UserIdentifier changed from " + oldIdentifier + " to " + newIdentifier);
    }
    
    @Path("token")
    @DELETE
    public Response deleteToken() {
        User u;

        try {
            u = findUserOrDie();
        } catch (WrappedResponse ex) {
            return ex.getResponse();
        }
        AuthenticatedUser au;        
       
        try{
             au = (AuthenticatedUser) u; 
        } catch (ClassCastException e){ 
            //if we have a non-authenticated user we stop here.
            return notFound("Token for " + u.getIdentifier() + " not eligible for deletion.");
        }       
       
        authSvc.removeApiToken(au);
        return ok("Token for " + au.getUserIdentifier() + " deleted.");
        
    }
    
    @Path("token")
    @GET
    public Response getTokenExpirationDate() {
        User u;
        
        try {
            u = findUserOrDie();
        } catch (WrappedResponse ex) {
            return ex.getResponse();
        }      
        
        ApiToken token = authSvc.findApiToken(getRequestApiKey());
        
        if (token == null) {
            return notFound("Token " + getRequestApiKey() + " not found.");
        }
        
        return ok("Token " + getRequestApiKey() + " expires on " + token.getExpireTime());
        
    }
    
    @Path("token/recreate")
    @POST
    public Response recreateToken() {
        User u;

        try {
            u = findUserOrDie();
        } catch (WrappedResponse ex) {
            return ex.getResponse();
        }
        
        AuthenticatedUser au;        
        try{
             au = (AuthenticatedUser) u; 
        } catch (ClassCastException e){ 
            //if we have a non-authenticated user we stop here.
            return notFound("Token for " + u.getIdentifier() + " is not eligible for recreation.");
        } 
        

        authSvc.removeApiToken(au);

        ApiToken newToken = authSvc.generateApiTokenForUser(au);
        authSvc.save(newToken);

        return ok("New token for " + au.getUserIdentifier() + " is " + newToken.getTokenString());

    }
    
    @GET
    @Path(":me")
    public Response getAuthenticatedUserByToken() {

        String tokenFromRequestAPI = getRequestApiKey();

        AuthenticatedUser authenticatedUser = findUserByApiToken(tokenFromRequestAPI);
        if (authenticatedUser == null) {
            return error(Response.Status.BAD_REQUEST, "User with token " + tokenFromRequestAPI + " not found.");
        } else {
            return ok(json(authenticatedUser));
        }

    }

    @POST
    @Path("{identifier}/removeRoles")
    public Response removeUserRoles(@PathParam("identifier") String identifier) {
        try {
            AuthenticatedUser userToModify = authSvc.getAuthenticatedUser(identifier);
            if (userToModify == null) {
                return error(Response.Status.BAD_REQUEST, "Cannot find user based on " + identifier + ".");
            }
            execCommand(new RevokeAllRolesCommand(userToModify, createDataverseRequest(findUserOrDie())));
            return ok("Roles removed for user " + identifier + ".");
        } catch (WrappedResponse wr) {
            return wr.getResponse();
        }
    }

    @GET
    @Path("{identifier}/traces")
    public Response getTraces(@PathParam("identifier") String identifier) {
        try {
            AuthenticatedUser userToQuery = authSvc.getAuthenticatedUser(identifier);
            JsonObjectBuilder jsonObj = execCommand(new GetUserTracesCommand(createDataverseRequest(findUserOrDie()), userToQuery, null));
            return ok(jsonObj);
        } catch (WrappedResponse ex) {
            return ex.getResponse();
        }
    }

    private List<String> elements = Arrays.asList("roleAssignments","dataverseCreator", "dataversePublisher","datasetCreator", "datasetPublisher","dataFileCreator","dataFilePublisher","datasetVersionUsers","explicitGroups","guestbookEntries", "savedSearches");
    
    @GET
    @Path("{identifier}/traces/{element}")
    @Produces("text/csv, application/json")
    public Response getTraces(@Context Request req, @PathParam("identifier") String identifier, @PathParam("element") String element) {
        try {
            AuthenticatedUser userToQuery = authSvc.getAuthenticatedUser(identifier);
            if(!elements.contains(element)) {
                throw new BadRequestException("Not a valid element");
            }
            JsonObjectBuilder jsonObj = execCommand(new GetUserTracesCommand(createDataverseRequest(findUserOrDie()), userToQuery, element));
            
            List<Variant> vars = Variant
                    .mediaTypes(MediaType.valueOf(FileUtil.MIME_TYPE_CSV), MediaType.APPLICATION_JSON_TYPE)
                    .add()
                    .build();
            MediaType requestedType = req.selectVariant(vars).getMediaType();
            if ((requestedType != null) && (requestedType.equals(MediaType.APPLICATION_JSON_TYPE))) {
                return ok(jsonObj);
            
            }
            JsonArray items=null;
            try {
                items = jsonObj.build().getJsonObject("traces").getJsonObject(element).getJsonArray("items");
            } catch(Exception e) {
                return ok(jsonObj);
            }
            return ok(FileUtil.jsonArrayOfObjectsToCSV(items, items.getJsonObject(0).keySet().toArray(new String[0])), MediaType.valueOf(FileUtil.MIME_TYPE_CSV), element + ".csv");
        } catch (WrappedResponse ex) {
            return ex.getResponse();
        }
    }

    @POST
    @Path("login")
    @Produces("application/json")
    public Response login(String jsonBody) {
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
            return error( Response.Status.BAD_REQUEST, "Invalid JSON supplied");
        }

        try {
            AuthenticatedUser r = authSvc.getUpdateAuthenticatedUser(BuiltinAuthenticationProvider.PROVIDER_ID, authReq);
            session.setUser(r);
            String csrfToken = createCsrfToken();
            session.setCsrfToken(csrfToken);
            HashMap<String, Object> responseHeaders= new HashMap();
            responseHeaders.put(CSRF_TOKEN_HEADER_NAME, csrfToken);
            return ok("User logged in", responseHeaders);
        } catch (AuthenticationFailedException ex) {
            return error(Response.Status.UNAUTHORIZED, "Invalid user credentials provided");
        }
    }

    private String createCsrfToken() {
        return RandomStringUtils.random(CSRF_TOKEN_LENGTH, 0, 0, true, true, null, new SecureRandom());
    }

    // TODO: At the moment this is just a PoC for testing OIDC validation with nimbus, it is necessary to properly evolve and encapsulate this logic.
    @POST
    @Path("loginOidc/{idToken}")
    @Produces("application/json")
    public Response loginOidc(@PathParam("idToken") String idToken) {
        try {
            // IDTokenValidator idTokenValidator = new IDTokenValidator(new Issuer("https://localhost/auth/realms/oidc-realm"), new ClientID("oidc-client"), JWSAlgorithm.RS256, new URL("https://localhost/auth/realms/oidc-realm/protocol/openid-connect/certs"));
            // Using this way since we are facing issues while retrieving JWK from URL
            IDTokenValidator idTokenValidator = new IDTokenValidator(new Issuer("https://localhost/auth/realms/oidc-realm"), new ClientID("oidc-client"), JWSAlgorithm.RS256, new JWKSet(getJWKKey()));
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(idToken);
            idTokenValidator.validate(signedJWT, null);
            return ok("OIDC idToken validated");
        } catch (Exception e) {
            return error(Response.Status.UNAUTHORIZED, "Invalid user credentials provided: " + e.getMessage());
        }
    }

    // Retrieved from https://localhost/auth/realms/oidc-realm/protocol/openid-connect/certs
    // Should be edited to match your OIDC provider JWK
    // New mechanism idea: The JWK key value could be provided via Dataverse API when configuring an OIDC provider for Dataverse
    private JWK getJWKKey() throws ParseException {
        return JWK.parse("{\"kid\":\"2rKfDSA8sP4FO-PJ3SmKU4AqoDySdGS_eUj2bVq8PD8\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"tBOX-t86fCWWo5oO53kVfn1gCiPwi7-lgeObQofo2FP3hIwu6QOYiDyiSMpbPwKZ9A7pTk3nrutUewCCwHmwxtg2epKZRGH9J-0y6YHChDdw_4_DqTyhr-ysdyU6aCX_htG-y5FSll0k5vr8RV-Ah6QuK9OFtW17VoaR_6xsr6z_S9_6Dv2BmbjNp67oNMPZQ35lhFBBiWIJf56fJh3rrc-lSHHVBoDrA_HZRdC7PDGSnVkVqNx0OPz50wZv_X41jDCCBSBtUOZWV_kqWl2pF076Zmt4e6tnaUDcQh9wh6NCy4QgmA1yWmzP5CTcdMyaYPWJlWMuG-WuxCKNaKMd_Q\",\"e\":\"AQAB\",\"x5c\":[\"MIICozCCAYsCBgGE6Sr49TANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDApvaWRjLXJlYWxtMB4XDTIyMTIwNjIwMzgzOFoXDTMyMTIwNjIwNDAxOFowFTETMBEGA1UEAwwKb2lkYy1yZWFsbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQTl/rfOnwllqOaDud5FX59YAoj8Iu/pYHjm0KH6NhT94SMLukDmIg8okjKWz8CmfQO6U5N567rVHsAgsB5sMbYNnqSmURh/SftMumBwoQ3cP+Pw6k8oa/srHclOmgl/4bRvsuRUpZdJOb6/EVfgIekLivThbVte1aGkf+sbK+s/0vf+g79gZm4zaeu6DTD2UN+ZYRQQYliCX+enyYd663PpUhx1QaA6wPx2UXQuzwxkp1ZFajcdDj8+dMGb/1+NYwwggUgbVDmVlf5KlpdqRdO+mZreHurZ2lA3EIfcIejQsuEIJgNclpsz+Qk3HTMmmD1iZVjLhvlrsQijWijHf0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAcz77NtYHno6c8TYF9OSoxuCgzQ77eKKhPm6Rl8RBcsSFiqYwaapE6YC1Arpuj/GMc5fE9/FiFaBQfldDUg4abA14WHmxD0y/YqpccsyVZv5jC/7CCbGFrJOD4qze3oHIM534sIcQl40NGUFXFfdnkz7wyOulLyDBl9FLnrEehntyT4/grX9hutppo0xPYt3lRpFe6NRg2hSYd4W3bJoX5+7KuJaNGrvYCuQWsvz0XOQBDm9lwXzWs6N6m9f75bA125tDefxkY3K4pQamxQC0vsoSs0f/QJBr6ZISppFDOBK9Z//9DSqC/LA5zoZyaIwMV9uP5dP1xvMDWtk2n0Yz1g==\"],\"x5t\":\"RIG0qyfQ-AOU1EosrgAS_N1CzOE\",\"x5t#S256\":\"9f4K2oLBi6GPwt_PqZIEmcOmpQOVem6OrfVCCBHMiXI\"}");
    }
}
