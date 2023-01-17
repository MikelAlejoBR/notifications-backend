package com.redhat.cloud.notifications.db.repositories;

import com.redhat.cloud.notifications.TestLifecycleManager;
import com.redhat.cloud.notifications.config.FeatureFlipper;
import com.redhat.cloud.notifications.db.ResourceHelpers;
import com.redhat.cloud.notifications.db.StatelessSessionFactory;
import com.redhat.cloud.notifications.models.Endpoint;
import com.redhat.cloud.notifications.models.HttpType;
import com.redhat.cloud.notifications.models.WebhookProperties;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.UUID;

import static com.redhat.cloud.notifications.models.EndpointType.WEBHOOK;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@QuarkusTestResource(TestLifecycleManager.class)
public class EndpointRepositoryTest {

    private static final int MAX_SERVER_ERRORS = 3;

    @Inject
    ResourceHelpers resourceHelpers;

    @Inject
    StatelessSessionFactory statelessSessionFactory;

    @Inject
    EndpointRepository endpointRepository;

    @Inject
    EntityManager entityManager;

    @Inject
    FeatureFlipper featureFlipper;

    @BeforeEach
    void beforeEach() {
        featureFlipper.setDisableWebhookEndpointsOnFailure(true);
    }

    @AfterEach
    void afterEach() {
        featureFlipper.setDisableWebhookEndpointsOnFailure(false);
    }

    @Test
    void testIncrementEndpointServerErrors() {
        Endpoint endpoint = resourceHelpers.createEndpoint(WEBHOOK, null, true, 0);
        assertTrue(endpoint.isEnabled());
        assertEquals(0, endpoint.getServerErrors());

        statelessSessionFactory.withSession(statelessSession -> {
            for (int i = 1; i <= MAX_SERVER_ERRORS + 1; i++) {
                assertEquals(i > MAX_SERVER_ERRORS, endpointRepository.incrementEndpointServerErrors(endpoint.getId(), MAX_SERVER_ERRORS));
                Endpoint ep = getEndpoint(endpoint.getId());
                assertEquals(i <= MAX_SERVER_ERRORS, ep.isEnabled());
                // The server errors counter is not incremented on the last iteration. The endpoint is disabled instead.
                assertEquals(i <= MAX_SERVER_ERRORS ? i : i - 1, ep.getServerErrors());
            }
        });
    }

    @Test
    void testIncrementEndpointServerErrorsWithUnknownId() {
        statelessSessionFactory.withSession(statelessSession -> {
            assertFalse(endpointRepository.incrementEndpointServerErrors(UUID.randomUUID(), 10));
        });
    }

    @Test
    void testResetEndpointServerErrorsWithExistingErrors() {
        Endpoint endpoint = resourceHelpers.createEndpoint(WEBHOOK, null, true, 3);
        assertEquals(3, endpoint.getServerErrors());
        statelessSessionFactory.withSession(statelessSession -> {
            assertTrue(endpointRepository.resetEndpointServerErrors(endpoint.getId()), "Endpoints with serverErrors > 0 SHOULD be updated");
            assertEquals(0, getEndpoint(endpoint.getId()).getServerErrors());
        });
    }

    @Test
    void testResetEndpointServerErrorsWithoutExistingErrors() {
        Endpoint endpoint = resourceHelpers.createEndpoint(WEBHOOK, null, true, 0);
        assertEquals(0, endpoint.getServerErrors());
        statelessSessionFactory.withSession(statelessSession -> {
            assertFalse(endpointRepository.resetEndpointServerErrors(endpoint.getId()), "Endpoints with serverErrors == 0 SHOULD NOT be updated");
            assertEquals(0, getEndpoint(endpoint.getId()).getServerErrors());
        });
    }

    @Test
    void testResetEndpointServerErrorsWithUnknownId() {
        statelessSessionFactory.withSession(statelessSession -> {
            assertFalse(endpointRepository.resetEndpointServerErrors(UUID.randomUUID()));
        });
    }

    @Test
    void testDisableEndpointWithEnabledEndpoint() {
        Endpoint endpoint = resourceHelpers.createEndpoint(WEBHOOK, null, true, 3);
        assertTrue(endpoint.isEnabled());
        statelessSessionFactory.withSession(statelessSession -> {
            assertTrue(endpointRepository.disableEndpoint(endpoint.getId()), "Enabled endpoints SHOULD be updated");
            assertFalse(getEndpoint(endpoint.getId()).isEnabled());
        });
    }

    @Test
    void testDisableEndpointWithDisabledEndpoint() {
        Endpoint endpoint = resourceHelpers.createEndpoint(WEBHOOK, null, false, 0);
        assertFalse(endpoint.isEnabled());
        statelessSessionFactory.withSession(statelessSession -> {
            assertFalse(endpointRepository.disableEndpoint(endpoint.getId()), "Disabled endpoints SHOULD NOT be updated");
            assertFalse(getEndpoint(endpoint.getId()).isEnabled());
        });
    }

    @Test
    void testDisableEndpointWithUnknownId() {
        statelessSessionFactory.withSession(statelessSession -> {
            assertFalse(endpointRepository.disableEndpoint(UUID.randomUUID()));
        });
    }

    Endpoint getEndpoint(UUID id) {
        String hql = "FROM Endpoint WHERE id = :id";
        return statelessSessionFactory.getCurrentSession().createQuery(hql, Endpoint.class)
                .setParameter("id", id)
                .getSingleResult();
    }

    /**
     * Tests that the "findByUuid" function works as expected. The test creates an endpoint first, and then fetches
     * it to ensure that the function works.
     */
    @Test
    void findByUuidAndOrgIdTest() {
        final String orgId = "find-by-uuid-org-id-test";

        final Endpoint endpoint = new Endpoint();
        endpoint.setCreated(LocalDateTime.now());
        endpoint.setDescription("Endpoint description");
        endpoint.setEnabled(true);
        endpoint.setId(UUID.randomUUID());
        endpoint.setName("endpoint-" + new SecureRandom().nextInt());
        endpoint.setOrgId(orgId);
        endpoint.setServerErrors(123);
        endpoint.setType(WEBHOOK);

        final WebhookProperties webhookProperties = new WebhookProperties();
        webhookProperties.setId(UUID.randomUUID());
        webhookProperties.setBasicAuthenticationSourcesId(512L);
        webhookProperties.setDisableSslVerification(true);
        webhookProperties.setEndpoint(endpoint);
        webhookProperties.setMethod(HttpType.PUT);
        webhookProperties.setSecretTokenSourcesId(213L);
        webhookProperties.setUrl("https://example.org");

        // Since we are not using a repository to create the associated
        // properties, we do it manually by first storing the endpoint and then
        // its properties.
        this.statelessSessionFactory.withSession(statelessSession -> {
            statelessSession.insert(endpoint);
            statelessSession.insert(webhookProperties);
        });

        final Endpoint[] dbEndpoints = new Endpoint[1];

        // Call the function under test.
        this.statelessSessionFactory.withSession(statelessSession -> {
            dbEndpoints[0] = this.endpointRepository.findByUuidAndOrgId(endpoint.getId(), orgId);
        });

        Assertions.assertEquals(1, dbEndpoints.length, "only one endpoint should have been fetched");

        final Endpoint dbEndpoint = dbEndpoints[0];

        Assertions.assertEquals(endpoint.getId(), dbEndpoint.getId(), "unexpected id from the fetched endpoint");
        Assertions.assertEquals(endpoint.getType(), dbEndpoint.getType(), "unexpected endpoint type from the fetched endpoint");
        Assertions.assertTrue(dbEndpoint.isEnabled(), "unexpected enabled value from the fetched endpoint");
        Assertions.assertEquals(endpoint.getServerErrors(), dbEndpoint.getServerErrors(), "unexpected server errors value from the fetched endpoint");

        Assertions.assertNotNull(dbEndpoint.getProperties());

        final WebhookProperties dbProperties = dbEndpoint.getProperties(WebhookProperties.class);
        Assertions.assertEquals(webhookProperties.getId(), dbProperties.getId(), "the ID of the associated properties doesn't match");
        Assertions.assertEquals(webhookProperties.getBasicAuthenticationSourcesId(), dbProperties.getBasicAuthenticationSourcesId(), "unexpected basic authentication sources id value");
        Assertions.assertEquals(webhookProperties.getDisableSslVerification(), dbProperties.getDisableSslVerification(), "unexpected ssl verification value");
        Assertions.assertEquals(webhookProperties.getMethod(), dbProperties.getMethod(), "unexpected http method value");
        Assertions.assertEquals(webhookProperties.getSecretTokenSourcesId(), dbProperties.getSecretTokenSourcesId(), "unexpected secret token sources ID value");
        Assertions.assertEquals(webhookProperties.getUrl(), dbProperties.getUrl(), "unexpected url value");
    }

    /**
     * Tests that the function under test throws a "NoResultException" whenever
     * the endpoint cannot be found.
     */
    @Test
    void findByUuidAndOrgIdNotFound() {
        // Call the function under test.
        this.statelessSessionFactory.withSession(statelessSession -> {
            Assertions.assertThrows(NoResultException.class, () ->
                this.endpointRepository.findByUuidAndOrgId(UUID.randomUUID(), "random-org-id")
            );
        });
    }

    /**
     * Tests that the function under test throws a "NoResultException" when the
     * endpoint ID is correct, but the Org ID doesn't match.
     */
    @Test
    void findByUuidAndOrgIdWrongOrgId() {
        final Endpoint endpoint = new Endpoint();
        endpoint.setCreated(LocalDateTime.now());
        endpoint.setDescription("Endpoint description");
        endpoint.setEnabled(true);
        endpoint.setId(UUID.randomUUID());
        endpoint.setName("endpoint-" + new SecureRandom().nextInt());
        endpoint.setOrgId("find-by-uuid-org-id-wrong-org-id-test");
        endpoint.setServerErrors(123);
        endpoint.setType(WEBHOOK);

        this.statelessSessionFactory.withSession(statelessSession -> {
            statelessSession.insert(endpoint);
        });

        // Call the function under test.
        this.statelessSessionFactory.withSession(statelessSession -> {
            Assertions.assertThrows(NoResultException.class, () ->
                this.endpointRepository.findByUuidAndOrgId(endpoint.getId(), "random-org-id")
            );
        });
    }
}
