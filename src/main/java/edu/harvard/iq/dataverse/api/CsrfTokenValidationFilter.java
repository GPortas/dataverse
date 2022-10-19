package edu.harvard.iq.dataverse.api;

import org.apache.http.HttpStatus;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import java.io.IOException;


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

        if (httpRequest.getMethod().equals(HttpMethod.GET)) {
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
}
