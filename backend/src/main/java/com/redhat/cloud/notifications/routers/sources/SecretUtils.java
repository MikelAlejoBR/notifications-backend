package com.redhat.cloud.notifications.routers.sources;

import com.redhat.cloud.notifications.models.BasicAuthentication;
import com.redhat.cloud.notifications.models.Endpoint;
import com.redhat.cloud.notifications.models.EndpointProperties;
import com.redhat.cloud.notifications.models.SourcesSecretable;
import org.eclipse.microprofile.rest.client.inject.RestClient;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

@ApplicationScoped
public class SecretUtils {

    /**
     * Used to manage the secrets on Sources.
     */
    @Inject
    @RestClient
    SourcesService sourcesService;

    /**
     * Gets the endpoint's secrets from Sources.
     * @param endpoint the endpoint to get the secrets from.
     */
    public void getSecretsForEndpoint(Endpoint endpoint) {
        EndpointProperties endpointProperties = endpoint.getProperties();

        if (endpointProperties instanceof SourcesSecretable) {
            var props = (SourcesSecretable) endpointProperties;

            final long basicAuthSourcesId = props.getBasicAuthenticationSourcesId();
            if (basicAuthSourcesId > 0) {
                final Secret secret = this.sourcesService.getById(basicAuthSourcesId);

                props.setBasicAuthentication(
                    new BasicAuthentication(
                        secret.username,
                        secret.password
                    )
                );
            }

            final long secretTokenSourcesId = props.getSecretTokenSourcesId();
            if (secretTokenSourcesId > 0) {
                final Secret secret = this.sourcesService.getById(secretTokenSourcesId);

                props.setSecretToken(secret.password);
            }
        }
    }

    /**
     * Creates the endpoint's secrets in Sources.
     * @param endpoint the endpoint to create the secrets from.
     */
    public void createSecretsForEndpoint(Endpoint endpoint) {
        EndpointProperties endpointProperties = endpoint.getProperties();

        if (endpointProperties instanceof SourcesSecretable) {
            var props = (SourcesSecretable) endpointProperties;

            final BasicAuthentication basicAuth = props.getBasicAuthentication();
            if (basicAuth != null) {
                Secret secret = new Secret();

                secret.authenticationType = Secret.TYPE_BASIC_AUTH;
                secret.password = basicAuth.getPassword();
                secret.username = basicAuth.getUsername();

                final Secret createdSecret = this.sourcesService.create(secret);

                props.setBasicAuthenticationSourcesId(createdSecret.id);
            }

            final String secretToken = props.getSecretToken();
            if (secretToken != null) {
                Secret secret = new Secret();

                secret.authenticationType = Secret.TYPE_SECRET_TOKEN;
                secret.password = secretToken;

                final Secret createdSecret = this.sourcesService.create(secret);

                props.setSecretTokenSourcesId(createdSecret.id);
            }
        }
    }

    /**
     * Updates the endpoint's secrets in Sources. It doesn't send the update request if the secret stored in Sources
     * and the updated secret are the same.
     * @param endpoint the endpoint to update the secrets from.
     */
    public void updateSecretsForEndpoint(Endpoint endpoint) {
        EndpointProperties endpointProperties = endpoint.getProperties();

        if (endpointProperties instanceof SourcesSecretable) {
            var props = (SourcesSecretable) endpointProperties;

            final BasicAuthentication basicAuth = props.getBasicAuthentication();
            final long basicAuthId = props.getBasicAuthenticationSourcesId();
            if (basicAuth != null && basicAuthId > 0) {
                Secret secret = new Secret();

                secret.password = basicAuth.getPassword();
                secret.username = basicAuth.getUsername();

                this.sourcesService.update(basicAuthId, secret);
                Log.infof("[endpoint_id: %s][secret_id: %s] Basic authentication secret updated in Sources", endpoint.getId(), basicAuthId);
            }

            final String secretToken = props.getSecretToken();
            final long secretTokenId = props.getSecretTokenSourcesId();
            if (secretToken != null && secretTokenId > 0) {
                Secret secret = new Secret();

                secret.password = secretToken;

                this.sourcesService.update(secretTokenId, secret);
                Log.infof("[endpoint_id: %s][secret_id: %s] Secret token secret updated in Sources", endpoint.getId(), secretTokenId);
            }
        }
    }

    /**
     * Deletes the endpoint's secrets. It requires for the properties to have a "basic authentication" ID and "secret
     * token" ID on the database.
     * @param endpoint the endpoint to delete the secrets from.
     */
    public void deleteSecretsForEndpoint(Endpoint endpoint) {
        EndpointProperties endpointProperties = endpoint.getProperties();

        if (endpointProperties instanceof SourcesSecretable) {
            var props = (SourcesSecretable) endpointProperties;

            final long basicAuthId = props.getBasicAuthenticationSourcesId();
            if (basicAuthId > 0) {
                this.sourcesService.delete(basicAuthId);
            }

            final long secretTokenId = props.getSecretTokenSourcesId();
            if (secretTokenId > 0) {
                this.sourcesService.delete(secretTokenId);
            }
        }
    }
}