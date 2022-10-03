package org.pac4j.demo.jee;

import org.pac4j.core.authorization.authorizer.IsAnonymousAuthorizer;
import org.pac4j.core.authorization.authorizer.IsAuthenticatedAuthorizer;
import org.pac4j.core.authorization.authorizer.RequireAnyRoleAuthorizer;
import org.pac4j.core.client.Clients;
import org.pac4j.core.client.direct.AnonymousClient;
import org.pac4j.core.config.Config;
import org.pac4j.core.matching.matcher.PathMatcher;
import org.pac4j.oidc.client.GoogleOidcClient;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import java.util.Optional;

/**
 * Pac4J configuration used for demonstration and experimentation.
 *
 * @author Phillip Ross
 */
@Dependent
public class SecurityConfig {

    /** The static logger instance. */
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    public static final String JWT_SALT = "12345678901234567890123456789012";

    /**
     * Build the Pac4J-specific configuration.
     *
     * @return a Pac4J config containing clients, authorizers, etc
     */
    @Produces @ApplicationScoped
    private Config buildConfiguration() {
        final OidcConfiguration oidcConfiguration = new OidcConfiguration();
        oidcConfiguration.setClientId("javaDemoClient");
        oidcConfiguration.setSecret("secret");
        oidcConfiguration.setUseNonce(true);
        oidcConfiguration.setDiscoveryURI("https://qaautenticaciondigital.and.gov.co/.well-known/openid-configuration");
        oidcConfiguration.addCustomParam("prompt", "consent");
        final OidcClient oidcClient = new OidcClient(oidcConfiguration);
        final Clients clients = new Clients(
                "http://localhost:9090/callback",
                oidcClient,
                new AnonymousClient()
        );
        final Config config = new Config(clients);
        config.addAuthorizer("admin", new RequireAnyRoleAuthorizer("ROLE_ADMIN"));
        config.addAuthorizer("custom", new CustomAuthorizer());
        config.addAuthorizer("mustBeAnon", new IsAnonymousAuthorizer("/?mustBeAnon"));
        config.addAuthorizer("mustBeAuth", new IsAuthenticatedAuthorizer("/?mustBeAuth"));
        config.addMatcher("excludedPath", new PathMatcher().excludeRegex("^/facebook/notprotected\\.action$"));
        return config;
    }
}
