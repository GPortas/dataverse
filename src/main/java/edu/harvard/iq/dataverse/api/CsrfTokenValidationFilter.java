package edu.harvard.iq.dataverse.api;

import edu.harvard.iq.dataverse.DataverseSession;
import org.apache.http.HttpStatus;

import javax.inject.Inject;
import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static edu.harvard.iq.dataverse.api.Users.CSRF_TOKEN_HEADER_NAME;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;


/**
 * A filter that validates the CSRF token of an incoming request to prevent CSRF attacks.
 *
 * @author GPortas
 */
public class CsrfTokenValidationFilter implements Filter {

    @Inject
    protected DataverseSession session;
    private static final String CSRF_BLOCK_RESPONSE_BODY = "{status:\"error\",message:\"Request blocked by CSRF filter\"}";
    private static final String URL_PATH_API_USERS_LOGIN = "/api/v1/users/login";
    private static final String COOKIE_NAME_JSESSIONID = "JSESSIONID";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (httpRequest.getRequestURI().startsWith(URL_PATH_API_USERS_LOGIN) || !isSessionBasedRequest(httpRequest)) {
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
            httpResponse.setContentType(APPLICATION_JSON);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }

    private static Boolean isSessionBasedRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return false;
        }
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(COOKIE_NAME_JSESSIONID)) {
                return true;
            }
        }
        return false;
    }
}
