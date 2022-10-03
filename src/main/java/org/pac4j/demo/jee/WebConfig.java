package org.pac4j.demo.jee;

import org.pac4j.core.config.Config;
import org.pac4j.jee.util.FilterHelper;
import org.pac4j.jee.filter.CallbackFilter;
import org.pac4j.jee.filter.LogoutFilter;
import org.pac4j.jee.filter.SecurityFilter;
import org.pac4j.jee.saml.metadata.Saml2MetadataFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Initialized;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.ServletContext;

/**
 * Pac4J configuration used for demonstration and experimentation.
 *
 * @author Phillip Ross
 */
@Named
@ApplicationScoped
public class WebConfig {

    /** The static logger instance. */
    private static final Logger logger = LoggerFactory.getLogger(WebConfig.class);

    @Inject
    private Config config;

    /**
     * Programmatically define the web configuration.
     *
     * @param servletContext the servlet context in which the configuration will apply
     */
    public void build(@Observes @Initialized(ApplicationScoped.class) ServletContext servletContext) {
        logger.debug("building Web configuration...");

        final FilterHelper filterHelper = new FilterHelper(servletContext);

        final SecurityFilter indexFilter = new SecurityFilter(config, "AnonymousClient");
        filterHelper.addFilterMapping("indexFilter", indexFilter, "/");

        final CallbackFilter callbackFilter = new CallbackFilter(config, "/");
        callbackFilter.setRenewSession(true);
        filterHelper.addFilterMapping("callbackFilter", callbackFilter, "/callback");

        final SecurityFilter jwtParameterFilter = new SecurityFilter(config, "ParameterClient");
        filterHelper.addFilterMapping("jwtParameterFilter", jwtParameterFilter, "/rest-jwt/*");

        final SecurityFilter oidcFilter = new SecurityFilter(config, "OidcClient");
        filterHelper.addFilterMapping("oidcFilter", oidcFilter, "/oidc/*");

        final ForceLoginFilter forceLoginFilter = new ForceLoginFilter();
        filterHelper.addFilterMapping("forceLoginFilter", forceLoginFilter, "/forceLogin");

        final SecurityFilter protectedFilter = new SecurityFilter(config);
        filterHelper.addFilterMapping("protectedFilter", protectedFilter, "/protected/*");

        final SecurityFilter mustBeAuthFilter = new SecurityFilter(config, "AnonymousClient", "mustBeAuth");
        filterHelper.addFilterMapping("mustBeAuthFilter", mustBeAuthFilter, "/logout");

        final LogoutFilter logoutFilter = new LogoutFilter(config, "/?defaulturlafterlogout");
        logoutFilter.setDestroySession(true);
        filterHelper.addFilterMapping("logoutFilter", logoutFilter, "/logout");

        final LogoutFilter centralLogoutFilter = new LogoutFilter(config, "http://localhost:9090/?defaulturlafterlogoutafteridp");
        centralLogoutFilter.setDestroySession(true);
        centralLogoutFilter.setLocalLogout(false);
        centralLogoutFilter.setCentralLogout(true);
        centralLogoutFilter.setLogoutUrlPattern("http://localhost:9090/.*");
        filterHelper.addFilterMapping("centralLogoutFilter", centralLogoutFilter, "/centralLogout");
    }
}
