package com.redhat.cloud.notifications.routers.sources;

import com.redhat.cloud.notifications.models.BasicAuthentication;
import com.redhat.cloud.notifications.models.Endpoint;
import com.redhat.cloud.notifications.models.EndpointProperties;
import com.redhat.cloud.notifications.models.SourcesSecretable;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.quarkus.logging.Log;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import java.util.UUID;

@ApplicationScoped
public class SecretUtils {

    /**
     * Used to gather data regarding the number of times that Sources gets
     * called.
     */
    @Inject
    MeterRegistry meterRegistry;

    @ConfigProperty(name = "sources.psk")
    String sourcesPsk;

    /**
     * Used to manage the secrets on Sources.
     */
    @Inject
    @RestClient
    SourcesService sourcesService;

    private static final String SOURCES_TIMER = "sources.get.secret.request";

    /**
     * Loads the endpoint's secrets from Sources.
     * @param endpoint the endpoint to get the secrets from.
     */
    public void loadSecretsForEndpoint(Endpoint endpoint) {
        EndpointProperties endpointProperties = endpoint.getProperties();

        if (endpointProperties instanceof SourcesSecretable) {
            var props = (SourcesSecretable) endpointProperties;

            final Long basicAuthSourcesId = props.getBasicAuthenticationSourcesId();
            if (basicAuthSourcesId != null) {
                final Timer.Sample getSecretTimer = Timer.start(this.meterRegistry);

                try {
                    final Secret secret = this.sourcesService.getById(
                        endpoint.getOrgId(),
                        this.sourcesPsk,
                        basicAuthSourcesId
                    );

                    props.setBasicAuthentication(
                        new BasicAuthentication(
                            secret.username,
                            secret.password
                        )
                    );
                } catch (final WebApplicationException e) {
                    this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                } finally {
                    getSecretTimer.stop(this.meterRegistry.timer(SOURCES_TIMER));
                }
            }

            final Long secretTokenSourcesId = props.getSecretTokenSourcesId();
            if (secretTokenSourcesId != null) {
                final Timer.Sample getSecretTimer = Timer.start(this.meterRegistry);

                try {
                    final Secret secret = this.sourcesService.getById(
                        endpoint.getOrgId(),
                        this.sourcesPsk,
                        secretTokenSourcesId
                    );

                    props.setSecretToken(secret.password);
                } catch (final WebApplicationException e) {
                    this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                } finally {
                    getSecretTimer.stop(this.meterRegistry.timer(SOURCES_TIMER));
                }
            }
        }
    }

    /**
     * Creates the endpoint's secrets in Sources. In this case, the endpoint's
     * ID cannot be appended both to the logs or the potential errors with
     * Sources, since until the endpoint gets saved in the database, it doesn't
     * have a {@link UUID}.
     * @param endpoint the endpoint to create the secrets from.
     */
    public void createSecretsForEndpoint(Endpoint endpoint) {
        EndpointProperties endpointProperties = endpoint.getProperties();

        if (endpointProperties instanceof SourcesSecretable) {
            var props = (SourcesSecretable) endpointProperties;

            final BasicAuthentication basicAuth = props.getBasicAuthentication();
            if (!this.isBasicAuthNullOrBlank(basicAuth)) {
                final long id = this.createBasicAuthentication(basicAuth, endpoint.getOrgId());

                Log.infof("[secret_id: %s] Basic authentication secret created in Sources", id);

                props.setBasicAuthenticationSourcesId(id);
            }

            final String secretToken = props.getSecretToken();
            if (secretToken != null && !secretToken.isBlank()) {
                final long id = this.createSecretTokenSecret(secretToken, endpoint.getOrgId());

                Log.infof("[secret_id: %s] Secret token secret created in Sources", id);

                props.setSecretTokenSourcesId(id);
            }
        }
    }

    /**
     * <p>Updates the endpoint's secrets in Sources. However a few cases are covered for the secrets:</p>
     * <ul>
     *  <li>If the endpoint has an ID for the secret, and the incoming secret is {@code null}, it is assumed that the
     *  user wants the secret to be deleted.</li>
     *  <li>If the endpoint has an ID for the secret, and the incoming secret isn't {@code null}, then the secret is
     *  updated.</li>
     *  <li>If the endpoint doesn't have an ID for the secret, and the incoming secret is {@code null}, it's basically
     *  a NOP — although the attempt is logged for debugging purposes.</li>
     *  <li>If the endpoint doesn't have an ID for the secret, and the incoming secret isn't {@code null}, it is
     *  assumed that the user wants the secret to be created.</li>
     * </ul>
     * @param endpoint the endpoint to update the secrets from.
     */
    public void updateSecretsForEndpoint(Endpoint endpoint) {
        EndpointProperties endpointProperties = endpoint.getProperties();

        if (endpointProperties instanceof SourcesSecretable) {
            var props = (SourcesSecretable) endpointProperties;

            final BasicAuthentication basicAuth = props.getBasicAuthentication();
            final Long basicAuthId = props.getBasicAuthenticationSourcesId();
            if (basicAuthId != null) {
                if (this.isBasicAuthNullOrBlank(basicAuth)) {
                    try {
                        this.sourcesService.delete(
                            endpoint.getOrgId(),
                            this.sourcesPsk,
                            basicAuthId
                        );
                        Log.infof("[endpoint_id: %s][secret_id: %s] Basic authentication secret deleted in Sources during an endpoint update operation", endpoint.getId(), basicAuthId);

                        props.setBasicAuthenticationSourcesId(null);
                    } catch (final WebApplicationException e) {
                        this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                    }
                } else {
                    Secret secret = new Secret();

                    secret.password = basicAuth.getPassword();
                    secret.username = basicAuth.getUsername();

                    try {
                        this.sourcesService.update(
                            endpoint.getOrgId(),
                            this.sourcesPsk,
                            basicAuthId,
                            secret
                        );
                        Log.infof("[endpoint_id: %s][secret_id: %s] Basic authentication secret updated in Sources during an endpoint update operation", endpoint.getId(), basicAuthId);
                    } catch (final WebApplicationException e) {
                        this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                    }
                }
            } else {
                if (this.isBasicAuthNullOrBlank(basicAuth)) {
                    Log.debugf("[endpoint_id: %s] Basic authentication secret not created in Sources: the basic authentication object is null", endpoint.getId());
                } else {
                    try {
                        final long id = this.createBasicAuthentication(basicAuth, endpoint.getOrgId());
                        Log.infof("[endpoint_id: %s][secret_id: %s] Basic authentication secret created in Sources during an endpoint update operation", endpoint.getId(), id);

                        props.setBasicAuthenticationSourcesId(id);
                    } catch (final WebApplicationException e) {
                        this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                    }
                }
            }

            final String secretToken = props.getSecretToken();
            final Long secretTokenId = props.getSecretTokenSourcesId();
            if (secretTokenId != null) {
                if (secretToken == null || secretToken.isBlank()) {
                    try {
                        this.sourcesService.delete(
                            endpoint.getOrgId(),
                            this.sourcesPsk,
                            secretTokenId
                        );

                        props.setSecretTokenSourcesId(null);

                        Log.infof("[endpoint_id: %s][secret_id: %s] Secret token secret deleted in Sources during an endpoint update operation", endpoint.getId(), secretTokenId);
                    } catch (final WebApplicationException e) {
                        this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                    }
                } else {
                    Secret secret = new Secret();

                    secret.password = secretToken;

                    try {
                        this.sourcesService.update(
                            endpoint.getOrgId(),
                            this.sourcesPsk,
                            secretTokenId,
                            secret
                        );
                        Log.infof("[endpoint_id: %s][secret_id: %s] Secret token secret updated in Sources", endpoint.getId(), secretTokenId);
                    } catch (final WebApplicationException e) {
                        this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                    }
                }
            } else {
                if (secretToken == null || secretToken.isBlank()) {
                    Log.debugf("[endpoint_id: %s] Secret token secret not created in Sources: the secret token object is null or blank", endpoint.getId());
                } else {
                    try {
                        final long id = this.createSecretTokenSecret(secretToken, endpoint.getOrgId());

                        Log.infof("[endpoint_id: %s][secret_id: %s] Secret token secret created in Sources during an endpoint update operation", endpoint.getId(), id);

                        props.setSecretTokenSourcesId(id);
                    } catch (final WebApplicationException e) {
                        this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                    }
                }
            }
        }
    }

    /**
     * Deletes the endpoint's secrets. It requires for the properties to have a "basic authentication" ID or "secret
     * token" ID on the database.
     * @param endpoint the endpoint to delete the secrets from.
     */
    public void deleteSecretsForEndpoint(Endpoint endpoint) {
        EndpointProperties endpointProperties = endpoint.getProperties();

        if (endpointProperties instanceof SourcesSecretable) {
            var props = (SourcesSecretable) endpointProperties;

            final Long basicAuthId = props.getBasicAuthenticationSourcesId();
            if (basicAuthId != null) {
                try {
                    this.sourcesService.delete(
                        endpoint.getOrgId(),
                        this.sourcesPsk,
                        basicAuthId
                    );
                    Log.infof("[endpoint_id: %s][secret_id: %s] Basic authentication secret updated in Sources", endpoint.getId(), basicAuthId);
                } catch (final WebApplicationException e) {
                    this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                }
            }

            final Long secretTokenId = props.getSecretTokenSourcesId();
            if (secretTokenId != null) {
                try {
                    this.sourcesService.delete(
                        endpoint.getOrgId(),
                        this.sourcesPsk,
                        secretTokenId
                    );
                    Log.infof("[endpoint_id: %s][secret_id: %s] Secret token secret deleted in Sources", endpoint.getId(), secretTokenId);
                } catch (final WebApplicationException e) {
                    this.prependEndpointUuidToExceptionAndRethrow(endpoint.getId(), e);
                }
            }
        }
    }

    /**
     * Creates a "basic authentication" secret in Sources.
     * @param basicAuthentication the contents of the "basic authentication" secret.
     * @param orgId the organization id related to this operation for the tenant identification.
     * @return the id of the created secret.
     */
    private long createBasicAuthentication(final BasicAuthentication basicAuthentication, final String orgId) {
        Secret secret = new Secret();

        secret.authenticationType = Secret.TYPE_BASIC_AUTH;
        secret.password = basicAuthentication.getPassword();
        secret.username = basicAuthentication.getUsername();

        final Secret createdSecret = this.sourcesService.create(
            orgId,
            this.sourcesPsk,
            secret
        );

        return createdSecret.id;
    }

    /**
     * Creates a "secret token" secret in Sources.
     * @param secretToken the "secret token"'s contents.
     * @param orgId the organization id related to this operation for the tenant identification.
     * @return the id of the created secret.
     */
    private long createSecretTokenSecret(final String secretToken, final String orgId) {
        Secret secret = new Secret();

        secret.authenticationType = Secret.TYPE_SECRET_TOKEN;
        secret.password = secretToken;

        final Secret createdSecret = this.sourcesService.create(
            orgId,
            this.sourcesPsk,
            secret
        );

        return createdSecret.id;
    }

    /**
     * Checks whether the provided {@link BasicAuthentication} object is null, or if its inner password and username
     * fields are blank. If any of the username or password fields contain a non-blank string, then it is assumed that
     * the object is not blank.
     * @param basicAuthentication the object to check.
     * @return {@code true} if the object is null, or if the password and the username are blank.
     */
    protected boolean isBasicAuthNullOrBlank(final BasicAuthentication basicAuthentication) {
        if (basicAuthentication == null) {
            return true;
        }

        return (basicAuthentication.getPassword() == null || basicAuthentication.getPassword().isBlank()) &&
                (basicAuthentication.getUsername() == null || basicAuthentication.getUsername().isBlank());
    }

    /**
     * Prepends the endpoint's UUID to the thrown {@link WebApplicationException}
     * in the {@link SourcesService} to make it easier to debug what the
     * problem might have been. Then, it rethrows the exception.
     * @param endpointUuid the endpoint's UUID to prepend.
     * @param e the exception that was thrown by the {@link SourcesService}.
     */
    protected void prependEndpointUuidToExceptionAndRethrow(final UUID endpointUuid, final WebApplicationException e) {
        throw new WebApplicationException(
            String.format("[endpoint_uuid: %s]%s", endpointUuid, e.getMessage()),
            e.getResponse()
        );
    }
}
