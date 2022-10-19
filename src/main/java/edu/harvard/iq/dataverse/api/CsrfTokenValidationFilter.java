package edu.harvard.iq.dataverse.api;

import org.apache.http.HttpStatus;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import java.io.IOException;

import static edu.harvard.iq.dataverse.api.AbstractApiBean.*;


/**
 * A filter that validates CSRF tokens to prevent CSRF attacks.
 *
 * @author GPortas
 */
public class CsrfTokenValidationFilter extends CsrfFilter {

    private static final String CSRF_BLOCK_RESPONSE_BODY = "{status:\"error\",message:\"Request blocked by CSRF filter\"}";
    private static final String CSRF_BLOCK_RESPONSE_CONTENT_TYPE = "application/json";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (httpRequest.getMethod().equals(HttpMethod.GET) || isKeyBasedRequest(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        String csrfToken = httpRequest.getHeader(CSRF_TOKEN_HEADER_NAME);
        if (csrfToken != null && session.isCsrfTokenRegistered(csrfToken)) {
            chain.doFilter(request, response);
        } else {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.getWriter().println(CSRF_BLOCK_RESPONSE_BODY);
            httpResponse.setStatus(HttpStatus.SC_FORBIDDEN);
            httpResponse.setContentType(CSRF_BLOCK_RESPONSE_CONTENT_TYPE);
        }
    }

    private boolean isKeyBasedRequest(HttpServletRequest httpRequest) {
        final String requestApiKey = getRequestApiKey(httpRequest);
        final String requestWFKey = getRequestWorkflowInvocationID(httpRequest);

        return requestApiKey != null || requestWFKey != null;
    }

    private String getRequestApiKey(HttpServletRequest httpRequest) {
        String headerParamApiKey = httpRequest.getHeader(DATAVERSE_KEY_HEADER_NAME);
        String queryParamApiKey = httpRequest.getParameter(DATAVERSE_KEY_PARAMETER_NAME);

        return headerParamApiKey != null ? headerParamApiKey : queryParamApiKey;
    }

    private String getRequestWorkflowInvocationID(HttpServletRequest httpRequest) {
        String headerParamWFKey = httpRequest.getHeader(DATAVERSE_WORKFLOW_INVOCATION_HEADER_NAME);
        String queryParamWFKey = httpRequest.getParameter(DATAVERSE_WORKFLOW_INVOCATION_PARAMETER_NAME);

        return headerParamWFKey != null ? headerParamWFKey : queryParamWFKey;
    }
}
