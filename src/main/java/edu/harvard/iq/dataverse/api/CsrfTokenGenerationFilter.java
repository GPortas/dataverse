package edu.harvard.iq.dataverse.api;

import org.apache.commons.lang.RandomStringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;


/**
 * A filter that generates a CSRF token to prevent CSRF attacks.
 *
 * @author GPortas
 */
public class CsrfTokenGenerationFilter extends CsrfFilter {

    private static final int CSRF_TOKEN_LENGTH = 20;

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String csrfToken = createCsrfToken();
        session.registerCsrfToken(csrfToken);
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setHeader(CSRF_TOKEN_HEADER_NAME, csrfToken);
        chain.doFilter(request, response);
    }

    private String createCsrfToken() {
        return RandomStringUtils.random(CSRF_TOKEN_LENGTH, 0, 0, true, true, null, new SecureRandom());
    }
}
