package edu.harvard.iq.dataverse.api;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.Response;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObjectBuilder;

import static com.jayway.restassured.RestAssured.given;
import static javax.ws.rs.core.Response.Status.OK;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;
import static org.junit.Assert.assertEquals;
import static org.hamcrest.CoreMatchers.equalTo;


public class LoginIT {

    public static final String API_BASE_PATH = "/api/login/";

    @BeforeClass
    public static void setUpClass() {
        RestAssured.baseURI = UtilIT.getRestAssuredBaseUri();
    }

    @Test
    public void testBuiltinLogin() {
        Response createUser = UtilIT.createRandomUser();
        createUser.prettyPrint();
        assertEquals(OK.getStatusCode(), createUser.getStatusCode());

        String usernameOfUser = UtilIT.getUsernameFromResponse(createUser);
        String loginEndpoint = API_BASE_PATH + "builtinLogin";

        // Shouldn't be able to log in with invalid credentials

        JsonObjectBuilder invalidCredentialsData = Json.createObjectBuilder();
        invalidCredentialsData.add("username", usernameOfUser);
        invalidCredentialsData.add("password", "wrongpassword");

        Response invalidCredentialsLoginResponse = given().body(invalidCredentialsData.build().toString()).post(loginEndpoint);
        invalidCredentialsLoginResponse.prettyPrint();
        invalidCredentialsLoginResponse.then().assertThat().body("message", equalTo("Invalid user credentials provided")).statusCode(UNAUTHORIZED.getStatusCode());

        // Should be able to log in with valid credentials

        JsonObjectBuilder validCredentialsData = Json.createObjectBuilder();
        validCredentialsData.add("username", usernameOfUser);
        validCredentialsData.add("password", usernameOfUser);

        Response successfulLoginResponse = given().body(validCredentialsData.build().toString()).post(loginEndpoint);
        successfulLoginResponse.prettyPrint();
        successfulLoginResponse.then().assertThat().body("data.message", equalTo("User logged in")).statusCode(OK.getStatusCode());
    }
}
