package edu.harvard.iq.dataverse.api;

import edu.harvard.iq.dataverse.DataverseSession;
import org.apache.http.HttpStatus;

import javax.inject.Inject;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static edu.harvard.iq.dataverse.api.AbstractApiBean.*;
import static edu.harvard.iq.dataverse.api.Users.CSRF_TOKEN_HEADER_NAME;


/**
 * A filter that validates the CSRF token of an incoming request to prevent CSRF attacks.
 *
 * @author GPortas
 */
public class CsrfTokenValidationFilter implements Filter {

    @Inject
    protected DataverseSession session;
    private static final String CSRF_BLOCK_RESPONSE_BODY = "{status:\"error\",message:\"Request blocked by CSRF filter\"}";
    private static final String CSRF_BLOCK_RESPONSE_CONTENT_TYPE = "application/json";
    private static final String URL_PATH_API_USERS_LOGIN = "/api/v1/users/login";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (httpRequest.getRequestURI().startsWith(URL_PATH_API_USERS_LOGIN) || isKeyBasedRequest(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        String incomingCsrfToken = httpRequest.getHeader(CSRF_TOKEN_HEADER_NAME);
        if (incomingCsrfToken != null && incomingCsrfToken.equals(session.getCsrfToken())) {
            chain.doFilter(request, response);
        } else {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            httpResponse.getWriter().println(CSRF_BLOCK_RESPONSE_BODY);
            httpResponse.setStatus(HttpStatus.SC_FORBIDDEN);
            httpResponse.setContentType(CSRF_BLOCK_RESPONSE_CONTENT_TYPE);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
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
