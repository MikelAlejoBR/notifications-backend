package com.redhat.cloud.notifications.routers.internal;

import com.redhat.cloud.notifications.TestLifecycleManager;
import com.redhat.cloud.notifications.db.ResourceHelpers;
import com.redhat.cloud.notifications.db.repositories.EndpointRepository;
import com.redhat.cloud.notifications.models.BasicAuthentication;
import com.redhat.cloud.notifications.models.CamelProperties;
import com.redhat.cloud.notifications.models.Endpoint;
import com.redhat.cloud.notifications.models.EndpointProperties;
import com.redhat.cloud.notifications.models.SourcesSecretable;
import com.redhat.cloud.notifications.models.WebhookProperties;
import com.redhat.cloud.notifications.routers.sources.Secret;
import com.redhat.cloud.notifications.routers.sources.SourcesService;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.mockito.InjectMock;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.redhat.cloud.notifications.Constants.API_INTERNAL;
import static com.redhat.cloud.notifications.TestConstants.DEFAULT_ORG_ID;
import static com.redhat.cloud.notifications.TestHelpers.createTurnpikeIdentityHeader;
import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;

@Deprecated(forRemoval = true)
@QuarkusTest
@QuarkusTestResource(TestLifecycleManager.class)
public class SourcesSecretsMigrationServiceTest {

    @Inject
    EndpointRepository endpointRepository;

    @Inject
    EntityManager entityManager;

    @Inject
    ResourceHelpers resourceHelpers;

    @Inject
    Session session;

    @InjectMock
    @RestClient
    SourcesService sourcesService;

    @ConfigProperty(name = "internal.admin-role")
    String adminRole;

    @ConfigProperty(name = "sources.psk")
    String sourcesPsk;

    /**
     * Tests that the endpoint under test calls the right number of times to
     * {@link SourcesService#create(String, String, Secret)}, with the proper
     * secrets.
     */
    @Deprecated(forRemoval = true)
    @Test
    public void testMigrateEndpointSecretsSources() {
        final Random random = new Random();

        // Creates ten endpoint fixtures that should be picked up by the
        // migration process. These endpoints contain both a basic
        // authentication object and a secret token that should be migrated.
        final Map<UUID, Endpoint> tenFullEndpoints = this.resourceHelpers.createTenEndpointFixtures();

        // Creates five more endpoints which have null or blank basic
        // authentication objects and valid secret tokens. Therefore, only the
        // secret tokens should be migrated.
        final Map<UUID, Endpoint> fivePartialEndpoints = this.resourceHelpers.createFiveEndpointsNullEmptyBasicAuths();

        // Create twelve more endpoints that should be ignored.
        this.resourceHelpers.createTwelveEndpointFixtures();

        // Merge all the created endpoints which should be picked by the
        // migration function.
        final Map<UUID, Endpoint> createdEndpoints = Stream
            .concat(
                tenFullEndpoints.entrySet().stream(),
                fivePartialEndpoints.entrySet().stream())
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        // Stores the generated stub secrets to verify that the "create" method
        // from the Sources service gets called appropriately.
        final Map<Long, Secret> generatedSecrets = new HashMap<>();

        // The following code block, even though verbosely, makes sure that
        // stubbed secrets are returned whenever the Sources service's "create"
        // method gets called. Essentially:
        //
        // 1. It creates a stubbed basic authentication secret, including the
        // ID that it should be generated by Sources.
        // 2. Sets up a Mock call so that that very same secret gets returned.
        // This way we avoid creating two secrets per stub call. The argument
        // matcher helps in this way, because it doesn't compare neither the
        // objects' references nor their ids.
        // 3. Adds the stubbed secret to the list above, so that we can call
        // Mockito's verify after the endpoint under test gets called.
        for (final Map.Entry<UUID, Endpoint> entry : createdEndpoints.entrySet()) {
            final Endpoint endpoint = entry.getValue();

            if (endpoint.getProperties() instanceof SourcesSecretable properties) {
                final BasicAuthentication basicAuthentication = properties.getBasicAuthentication();

                if (!this.isBasicAuthNullOrBlank(basicAuthentication)) {
                    final Secret stubbedBasicAuthSecret = new Secret();
                    stubbedBasicAuthSecret.id = random.nextLong(1, Long.MAX_VALUE);
                    stubbedBasicAuthSecret.authenticationType = Secret.TYPE_BASIC_AUTH;
                    stubbedBasicAuthSecret.password = properties.getBasicAuthentication().getPassword();
                    stubbedBasicAuthSecret.username = properties.getBasicAuthentication().getUsername();

                    // Store the generated stub for later checks.
                    generatedSecrets.put(stubbedBasicAuthSecret.id, stubbedBasicAuthSecret);

                    // Set up the stub call to return the generated secret.
                    Mockito.when(
                        this.sourcesService.create(Mockito.eq(DEFAULT_ORG_ID), Mockito.eq(this.sourcesPsk), Mockito.argThat(secretArgumentMatcher(stubbedBasicAuthSecret)))
                    ).thenReturn(stubbedBasicAuthSecret);
                }

                final Secret stubbedSecretTokenSecret = new Secret();
                stubbedSecretTokenSecret.id = random.nextLong(1, Long.MAX_VALUE);
                stubbedSecretTokenSecret.authenticationType = Secret.TYPE_SECRET_TOKEN;
                stubbedSecretTokenSecret.password = properties.getSecretToken();

                // Store the generated stub for later checks.
                generatedSecrets.put(stubbedSecretTokenSecret.id, stubbedSecretTokenSecret);

                // Set up the stub call to return the generated secret.
                Mockito.when(
                    this.sourcesService.create(Mockito.eq(DEFAULT_ORG_ID), Mockito.eq(this.sourcesPsk), Mockito.argThat(secretArgumentMatcher(stubbedSecretTokenSecret)))
                ).thenReturn(stubbedSecretTokenSecret);
            } else {
                throw new IllegalStateException("invalid endpoint properties type: " + endpoint.getProperties().getClass());
            }
        }

        // Call the endpoint under test.
        given()
            .basePath(API_INTERNAL)
            .header(createTurnpikeIdentityHeader("admin", adminRole))
            .when()
            .contentType(JSON)
            .post("/sources-migration")
            .then()
            .statusCode(204);

        // Verify that Sources got called once for each generated stub.
        for (final Map.Entry<Long, Secret> entry : generatedSecrets.entrySet()) {
            Mockito.verify(
                this.sourcesService,
                Mockito.times(1)
            ).create(Mockito.eq(DEFAULT_ORG_ID), Mockito.eq(this.sourcesPsk), Mockito.argThat(secretArgumentMatcher(entry.getValue())));
        }

        // Verify that sources got called the same number of times as stubs
        // were generated.
        Mockito.verify(
            this.sourcesService,
            Mockito.times(generatedSecrets.size())
        ).create(Mockito.eq(DEFAULT_ORG_ID), Mockito.eq(this.sourcesPsk), Mockito.any());

        // Verify that sources got called the RIGHT number of times.
        Mockito.verify(
            this.sourcesService,
            Mockito.times(tenFullEndpoints.size() * 2 + fivePartialEndpoints.size())
        ).create(Mockito.eq(DEFAULT_ORG_ID), Mockito.eq(this.sourcesPsk), Mockito.any());

        // Assert that the correct number of stubs were generated.
        Assertions.assertEquals(
            tenFullEndpoints.size() * 2 + fivePartialEndpoints.size(),
            generatedSecrets.size(),
            "unexpected number of stubs generated. There should have been 25 secrets, because we generate ten endpoints with both secrets, and five endpoints with just the secret token"
        );

        // Reload the properties from the database for the endpoints.
        this.endpointRepository.loadProperties(new ArrayList<>(createdEndpoints.values()));

        int updatedSecretReferencesInDatabase = 0;
        for (final Map.Entry<UUID, Endpoint> entry : createdEndpoints.entrySet()) {

            if (entry.getValue().getProperties() instanceof SourcesSecretable properties) {
                final Long basicAuthSourcesId = properties.getBasicAuthenticationSourcesId();
                final BasicAuthentication basicAuthentication = properties.getBasicAuthentication();

                // There might be null or blank basic authentications. In these
                // cases, just check the secret tokens...
                if (!this.isBasicAuthNullOrBlank(basicAuthentication)) {
                    final Secret basicAuthSecret = generatedSecrets.get(basicAuthSourcesId);
                    Assertions.assertNotNull(basicAuthSecret, "the stubbed basic authentication secret specified by the Sources reference was not found");

                    Assertions.assertEquals(basicAuthSecret.authenticationType, Secret.TYPE_BASIC_AUTH);
                    Assertions.assertEquals(basicAuthentication.getUsername(), basicAuthSecret.username);
                    Assertions.assertEquals(basicAuthentication.getPassword(), basicAuthSecret.password);

                    updatedSecretReferencesInDatabase++;
                }

                // ... because the secret tokens will always be not null and
                // not blank, at least in this test case.
                final long secretTokenSourcesId = properties.getSecretTokenSourcesId();

                final String secretToken = properties.getSecretToken();
                final Secret secretTokenSecret = generatedSecrets.get(secretTokenSourcesId);

                Assertions.assertNotNull(secretTokenSecret, "the stubbed secret token secret specified by the Sources reference was not found");

                Assertions.assertEquals(Secret.TYPE_SECRET_TOKEN, secretTokenSecret.authenticationType);
                Assertions.assertEquals(secretToken, secretTokenSecret.password);

                updatedSecretReferencesInDatabase++;
            } else {
                throw new IllegalStateException("invalid endpoint properties type: " + entry.getValue().getProperties().getClass());
            }
        }

        Assertions.assertEquals(generatedSecrets.size(), updatedSecretReferencesInDatabase, "unexpected number of updated Sources references found in the database");
    }

    /**
     * Tests that when exceptions are raised during the migration, the
     * execution continues. Also checks that when an exception occurs, then
     * the created Sources secrets are deleted from there too.
     */
    @Deprecated(forRemoval = true)
    @Test
    public void testExceptionContinuesExecution() {
        // Creates ten endpoint fixtures that should be picked up by the
        // migration process. However, these endpoints will be updated so that
        // they contain an invalid URL, which should cause an exception.
        // Therefore, these endpoints should trigger a rollback upon saving
        // them.
        final Map<UUID, Endpoint> tenFullEndpoints = this.resourceHelpers.createTenEndpointFixtures();

        // Set an invalid private "https://10.0.0.21" URL which should trigger
        // a constraint violation exception when attempting to save the
        // endpoint after updating its references to Sources secrets.
        for (final Map.Entry<UUID, Endpoint> entry : tenFullEndpoints.entrySet()) {
            this.setInvalidUrlForEndpoint(entry.getValue());
        }

        // Creates five more endpoints which have null or blank basic
        // authentication objects and valid secret tokens. Therefore, only the
        // secret tokens should be migrated.
        final Map<UUID, Endpoint> fivePartialEndpoints = this.resourceHelpers.createFiveEndpointsNullEmptyBasicAuths();

        // Return a secret every time the service gets called. In this case we
        // don't mind if the same ID is returned every time, since the goal of
        // this test isn't to check that the middleware logic works as
        // expected.
        final Secret stubSecret = new Secret();
        stubSecret.id = new Random().nextLong(1, Long.MAX_VALUE);
        Mockito.when(this.sourcesService.create(Mockito.anyString(), Mockito.anyString(), Mockito.any())).thenReturn(stubSecret);

        // Call the endpoint under test.
        given()
            .basePath(API_INTERNAL)
            .header(createTurnpikeIdentityHeader("admin", adminRole))
            .when()
            .contentType(JSON)
            .post("/sources-migration")
            .then()
            .statusCode(204);

        // The "delete secrets" operation should have been called double the
        // times as full endpoints were created.
        Mockito.verify(this.sourcesService, Mockito.times(tenFullEndpoints.size() * 2)).delete(Mockito.anyString(), Mockito.anyString(), Mockito.anyLong());

        // Verify that the ten full endpoints don't have any Sources references
        // stored in their database properties.
        for (final Map.Entry<UUID, Endpoint> entry : tenFullEndpoints.entrySet()) {
            final Endpoint endpoint = this.endpointRepository.getEndpoint(entry.getValue().getOrgId(), entry.getKey());
            Assertions.assertNotNull(endpoint, "the endpoint was not fetched from the database");

            final EndpointProperties endpointProperties = endpoint.getProperties();
            if (endpointProperties instanceof SourcesSecretable properties) {
                Assertions.assertNull(properties.getBasicAuthenticationSourcesId(), "the basic authentication Sources secret reference should not have been saved in the database");
                Assertions.assertNull(properties.getSecretTokenSourcesId(), "the secret token Sources secret reference should not have been saved in the database");
            } else {
                Assertions.fail("an endpoint was fetched which didn't have Sources secretable properties");
            }
        }

        // Verify that the five partial endpoints do have Sources secrets
        // references.
        for (final Map.Entry<UUID, Endpoint> entry : fivePartialEndpoints.entrySet()) {
            final Endpoint endpoint = this.endpointRepository.getEndpoint(entry.getValue().getOrgId(), entry.getKey());
            Assertions.assertNotNull(endpoint, "the endpoint was not fetched from the database");

            final EndpointProperties endpointProperties = endpoint.getProperties();
            if (endpointProperties instanceof SourcesSecretable properties) {
                final Long basicAuthSourcesId = properties.getBasicAuthenticationSourcesId();
                final Long secretTokenSourcesId = properties.getSecretTokenSourcesId();

                Assertions.assertTrue(
                    (basicAuthSourcesId != null) || (secretTokenSourcesId != null),
                    "either the basic authentication or the secret token should have a Sources reference, but none had it");
            } else {
                Assertions.fail("an endpoint was fetched which didn't have Sources secretable properties");
            }
        }
    }

    /**
     * Custom argument matcher which checks if two secrets are the same one. It
     * skips the {@link Secret#id} equals check and the reference check on
     * purpose, because the idea is that Mockito should return the stub based
     * on the contents of the secret, not based on if both object's references
     * match or if there is a present ID.
     * @param expectedSecret the expected secret to be matched with.
     * @return an argument matcher.
     */
    @Deprecated(forRemoval = true)
    private ArgumentMatcher<Secret> secretArgumentMatcher(final Secret expectedSecret) {
        return providedSecret ->
            Objects.equals(expectedSecret.authenticationType, providedSecret.authenticationType)
                && Objects.equals(expectedSecret.password, providedSecret.password)
                && Objects.equals(expectedSecret.username, providedSecret.username);
    }

    /**
     * Checks if the provided basic authentication is null or if its elements
     * are blank.
     * @param basicAuthentication the basic authentication to check.
     * @return true if the basic authentication is null or its elements are
     * blank.
     */
    @Deprecated(forRemoval = true)
    private boolean isBasicAuthNullOrBlank(final BasicAuthentication basicAuthentication) {
        return basicAuthentication == null
            || (basicAuthentication.getPassword() == null || basicAuthentication.getPassword().isBlank())
            || (basicAuthentication.getUsername() == null || basicAuthentication.getUsername().isBlank());
    }

    /**
     * Sets the given endpoint properties' URL field to an invalid URL, in
     * order to trigger a {@link javax.validation.ConstraintViolationException}
     * in the {@link SourcesSecretsMigrationService#migrateEndpointSecretsSources()}
     * function.
     * @param endpoint the endpoint which its URL will be set to an invalid
     *                 value.
     */
    @Deprecated(forRemoval = true)
    private void setInvalidUrlForEndpoint(final Endpoint endpoint) {
        final EndpointProperties endpointProperties = endpoint.getProperties();

        final StringBuilder sb = new StringBuilder();
        sb.append("UPDATE ");
        if (endpointProperties instanceof CamelProperties) {
            sb.append("CamelProperties AS p ");
            sb.append("SET p.url = 'http://10.0.0.21' ");
        } else if (endpointProperties instanceof WebhookProperties) {
            sb.append("WebhookProperties AS p ");
            sb.append("SET p.url = 'http://10.0.0.21' ");
        }
        sb.append("WHERE p.id = :uuid");

        final Transaction tx = this.session.beginTransaction();
        this.entityManager
            .createQuery(sb.toString())
            .setParameter("uuid", endpoint.getId())
            .executeUpdate();

        tx.commit();
    }
}
