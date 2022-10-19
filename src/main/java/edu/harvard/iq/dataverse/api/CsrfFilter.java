package edu.harvard.iq.dataverse.api;

import edu.harvard.iq.dataverse.DataverseSession;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;


/**
 *
 * @author GPortas
 */
public abstract class CsrfFilter implements Filter {

    @Inject
    protected DataverseSession session;

    protected static final String CSRF_TOKEN_HEADER_NAME = "X-CSRF-Token";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
