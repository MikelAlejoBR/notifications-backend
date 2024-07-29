package com.redhat.cloud.notifications.auth.kessel;

import com.redhat.cloud.notifications.auth.principal.ConsolePrincipal;
import com.redhat.cloud.notifications.auth.principal.rhid.RhIdPrincipal;
import com.redhat.cloud.notifications.auth.principal.rhid.RhIdentity;
import com.redhat.cloud.notifications.auth.principal.rhid.RhServiceAccountIdentity;
import com.redhat.cloud.notifications.auth.principal.rhid.RhUserIdentity;
import com.redhat.cloud.notifications.auth.principal.turnpike.TurnpikePrincipal;
import com.redhat.cloud.notifications.auth.principal.turnpike.TurnpikeSamlIdentity;
import com.redhat.cloud.notifications.config.BackendConfig;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.SecurityContext;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.project_kessel.api.relations.v1beta1.CheckRequest;
import org.project_kessel.api.relations.v1beta1.CheckResponse;
import org.project_kessel.api.relations.v1beta1.LookupResourcesRequest;
import org.project_kessel.api.relations.v1beta1.LookupResourcesResponse;
import org.project_kessel.api.relations.v1beta1.ObjectReference;
import org.project_kessel.api.relations.v1beta1.SubjectReference;
import org.project_kessel.relations.client.CheckClient;
import org.project_kessel.relations.client.LookupClient;

import java.security.Principal;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@QuarkusTest
public class KesselAuthorizationTest {
    @InjectMock
    BackendConfig backendConfig;

    @InjectMock
    CheckClient checkClient;

    @InjectMock
    LookupClient lookupClient;

    @Inject
    KesselAuthorization kesselAuthorization;

    /**
     * Tests that when the principal is authorized, the function under test
     * does not raise an exception.
     */
    @Test
    void testAuthorized() {
        // Mock the security context.
        final SecurityContext mockedSecurityContext = Mockito.mock(SecurityContext.class);

        // Create a RhIdentity principal and assign it to the mocked security
        // context.
        final RhIdentity identity = Mockito.mock(RhIdentity.class);
        Mockito.when(identity.getName()).thenReturn("Red Hat user");

        final ConsolePrincipal<?> principal = new RhIdPrincipal(identity);
        Mockito.when(mockedSecurityContext.getUserPrincipal()).thenReturn(principal);

        // Enable the Kessel back end integration for this test.
        Mockito.when(this.backendConfig.isKesselBackendEnabled()).thenReturn(true);

        // Simulate that Kessel returns a positive response.
        final CheckResponse positiveCheckResponse = CheckResponse.newBuilder().setAllowed(CheckResponse.Allowed.ALLOWED_TRUE).build();
        Mockito.when(this.checkClient.check(Mockito.any())).thenReturn(positiveCheckResponse);

        // Call the function under test.
        this.kesselAuthorization.hasPermissionOnResource(
            mockedSecurityContext,
            WorkspacePermission.EVENT_LOG_VIEW,
            ResourceType.WORKSPACE,
            "workspace-uuid"
        );

        // Verify that we called Kessel.
        Mockito.verify(this.checkClient, Mockito.times(1)).check(Mockito.any());
    }

    /**
     * Tests that when the principal is authorized, the function under test
     * throws an exception.
     */
    @Test
    void testUnauthorized() {
        // Mock the security context.
        final SecurityContext mockedSecurityContext = Mockito.mock(SecurityContext.class);

        // Create a RhIdentity principal and assign it to the mocked security
        // context.
        final RhIdentity identity = Mockito.mock(RhIdentity.class);
        Mockito.when(identity.getName()).thenReturn("Red Hat user");

        final ConsolePrincipal<?> principal = new RhIdPrincipal(identity);
        Mockito.when(mockedSecurityContext.getUserPrincipal()).thenReturn(principal);

        // Enable the Kessel back end integration for this test.
        Mockito.when(this.backendConfig.isKesselBackendEnabled()).thenReturn(true);

        // Simulate that Kessel returns a negative response.
        final CheckResponse positiveCheckResponse = CheckResponse.newBuilder().setAllowed(CheckResponse.Allowed.ALLOWED_FALSE).build();
        Mockito.when(this.checkClient.check(Mockito.any())).thenReturn(positiveCheckResponse);

        // Call the function under test and expect that it throws a "Forbidden"
        // exception.
        Assertions.assertThrows(
            ForbiddenException.class,
            () -> this.kesselAuthorization.hasPermissionOnResource(
                mockedSecurityContext,
                WorkspacePermission.EVENT_LOG_VIEW,
                ResourceType.WORKSPACE,
                "workspace-uuid"
            ),
            "unexpected exception thrown, as with a negative response from Kessel it should throw a \"Forbidden exception\""
        );

        // Verify that we called Kessel.
        Mockito.verify(this.checkClient, Mockito.times(1)).check(Mockito.any());
    }

    /**
     * Tests that the incoming integration UUID's are correctly parsed and
     * returned in a set.
     */
    @Test
    void testLookupAuthorizedIntegrations() {
        // Mock the security context.
        final SecurityContext mockedSecurityContext = Mockito.mock(SecurityContext.class);

        // Create a RhIdentity principal and assign it to the mocked security
        // context.
        final RhIdentity identity = Mockito.mock(RhIdentity.class);
        Mockito.when(identity.getName()).thenReturn("Red Hat user");

        final ConsolePrincipal<?> principal = new RhIdPrincipal(identity);
        Mockito.when(mockedSecurityContext.getUserPrincipal()).thenReturn(principal);

        // Enable the Kessel back end integration for this test.
        Mockito.when(this.backendConfig.isKesselBackendEnabled()).thenReturn(true);

        // Simulate that Kessel returns a few resource IDs in the response.
        final UUID firstUuid = UUID.randomUUID();
        final ObjectReference objectReferenceOne = ObjectReference.newBuilder().setId(firstUuid.toString()).build();
        final LookupResourcesResponse lookupResourcesResponseOne = LookupResourcesResponse.newBuilder().setResource(objectReferenceOne).build();

        final UUID secondUuid = UUID.randomUUID();
        final ObjectReference objectReferenceTwo = ObjectReference.newBuilder().setId(secondUuid.toString()).build();
        final LookupResourcesResponse lookupResourcesResponseTwo = LookupResourcesResponse.newBuilder().setResource(objectReferenceTwo).build();

        final UUID thirdUuid = UUID.randomUUID();
        final ObjectReference objectReferenceThree = ObjectReference.newBuilder().setId(thirdUuid.toString()).build();
        final LookupResourcesResponse lookupResourcesResponseThree = LookupResourcesResponse.newBuilder().setResource(objectReferenceThree).build();

        // Return the iterator to simulate a stream of incoming results from
        // Kessel.
        final List<LookupResourcesResponse> lookupResourcesResponses = List.of(lookupResourcesResponseOne, lookupResourcesResponseTwo, lookupResourcesResponseThree);
        Mockito.when(this.lookupClient.lookupResources(Mockito.any())).thenReturn(lookupResourcesResponses.iterator());

        // Call the function under test.
        final Set<UUID> result = this.kesselAuthorization.lookupAuthorizedIntegrations(mockedSecurityContext, IntegrationPermission.VIEW);

        // Assert that the result is the expected one.
        final Set<UUID> expectedUuids = Set.of(firstUuid, secondUuid, thirdUuid);

        result.forEach(r -> Assertions.assertTrue(expectedUuids.contains(r), String.format("UUID \"%s\" not present in the expected UUIDs", r)));
    }

    /**
     * Test that permission check requests are properly built for both service
     * accounts and users.
     */
    @Test
    void testBuildCheckRequest() {
        record TestCase(RhIdentity identity, String expectedIdentityType, ResourceType resourceType, KesselPermission permission, String resourceId) {
            @Override
            public String toString() {
                return "TestCase{" +
                    "identity='" + this.identity + '\'' +
                    ", expectedIdentityType='" + this.expectedIdentityType + '\'' +
                    ", resourceType='" + this.resourceType + '\'' +
                    ", kesselPermission='" + this.permission + '\'' +
                    ", resourceId='" + this.resourceId + '\'' +
                    '}';
            }
        }

        // Create a user identity object.
        final String username = "Red Hat user";
        final RhIdentity userIdentity = Mockito.mock(RhUserIdentity.class);
        Mockito.when(userIdentity.getName()).thenReturn(username);

        // Create a service account identity object.
        final String serviceAccountName = String.format("service-account-%s", UUID.randomUUID());
        final RhIdentity serviceAccountIdentity = Mockito.mock(RhServiceAccountIdentity.class);
        Mockito.when(serviceAccountIdentity.getName()).thenReturn(serviceAccountName);

        // Loop through the supported identities.
        final List<TestCase> testCases = List.of(
            new TestCase(userIdentity, KesselAuthorization.KESSEL_IDENTITY_SUBJECT_USER, ResourceType.INTEGRATION, IntegrationPermission.VIEW, "12345"),
            new TestCase(serviceAccountIdentity, KesselAuthorization.KESSEL_IDENTITY_SUBJECT_SERVICE_ACCOUNT, ResourceType.INTEGRATION, IntegrationPermission.EDIT, "54321"),
            new TestCase(userIdentity, KesselAuthorization.KESSEL_IDENTITY_SUBJECT_USER, ResourceType.WORKSPACE, WorkspacePermission.CREATE_DRAWER_INTEGRATION, "workspace-a"),
            new TestCase(serviceAccountIdentity, KesselAuthorization.KESSEL_IDENTITY_SUBJECT_SERVICE_ACCOUNT, ResourceType.WORKSPACE, WorkspacePermission.EVENT_LOG_VIEW, "workspace-b")
        );

        for (final TestCase tc : testCases) {
            // Call the function under test.
            final CheckRequest checkRequest = this.kesselAuthorization.buildCheckRequest(tc.identity(), tc.permission(), tc.resourceType(), tc.resourceId());

            // Make sure the request was built appropriately.
            final ObjectReference objectReference = checkRequest.getResource();
            Assertions.assertEquals(tc.resourceType().getKesselName(), objectReference.getType().getName(), String.format("unexpected resource type obtained for the object's reference on test case: %s", tc));
            Assertions.assertEquals(tc.resourceId(), objectReference.getId(), String.format("unexpected resource ID obtained for the object's reference on test case: %s", tc));

            Assertions.assertEquals(tc.permission().getKesselPermissionName(), checkRequest.getRelation(), String.format("unexpected relation obtained on test case: %s", tc));

            final SubjectReference subjectReference = checkRequest.getSubject();
            Assertions.assertEquals(tc.expectedIdentityType(), subjectReference.getSubject().getType().getName(), String.format("unexpected resource type obtained for the subject's reference on test case: %s", tc));
            Assertions.assertEquals(tc.identity().getName(), subjectReference.getSubject().getId(), String.format("unexpected resource ID obtained for the subject's reference on test case: %s", tc));
        }
    }

    /**
     * Tests that the "lookup resources" requests are properly built both for
     * service accounts and users.
     */
    @Test
    void testBuildLookupResourcesRequest() {
        record TestCase(RhIdentity identity, String expectedIdentityType, KesselPermission permission) {
            @Override
            public String toString() {
                return "TestCase{" +
                    "identity='" + this.identity + '\'' +
                    ", expectedIdentityType='" + this.expectedIdentityType + '\'' +
                    ", kesselPermission='" + this.permission + '\'' +
                    '}';
            }
        }

        // Create a user identity object.
        final String username = "Red Hat user";
        final RhIdentity userIdentity = Mockito.mock(RhUserIdentity.class);
        Mockito.when(userIdentity.getName()).thenReturn(username);

        // Create a service account identity object.
        final String serviceAccountName = String.format("service-account-%s", UUID.randomUUID());
        final RhIdentity serviceAccountIdentity = Mockito.mock(RhServiceAccountIdentity.class);
        Mockito.when(serviceAccountIdentity.getName()).thenReturn(serviceAccountName);

        // Loop through the supported identities.
        final List<TestCase> testCases = List.of(
            new TestCase(userIdentity, KesselAuthorization.KESSEL_IDENTITY_SUBJECT_USER, IntegrationPermission.VIEW),
            new TestCase(serviceAccountIdentity, KesselAuthorization.KESSEL_IDENTITY_SUBJECT_SERVICE_ACCOUNT, IntegrationPermission.VIEW)
        );

        for (final TestCase tc : testCases) {
            // Call the function under test.
            final LookupResourcesRequest lookupResourcesRequest = this.kesselAuthorization.buildLookupResourcesRequest(tc.identity(), tc.permission());

            // Make sure the request was built appropriately.
            final SubjectReference subjectReference = lookupResourcesRequest.getSubject();
            Assertions.assertEquals(tc.expectedIdentityType(), subjectReference.getSubject().getType().getName(), String.format("unexpected resource type obtained for the subject's reference on test case: %s", tc));
            Assertions.assertEquals(tc.identity().getName(), subjectReference.getSubject().getId(), String.format("unexpected resource ID obtained for the subject's reference on test case: %s", tc));

            Assertions.assertEquals(tc.permission().getKesselPermissionName(), lookupResourcesRequest.getRelation(), String.format("unexpected relation obtained on test case: %s", tc));

            Assertions.assertEquals(ResourceType.INTEGRATION.getKesselName(), lookupResourcesRequest.getResourceType().getName(), String.format("unexpected resource type obtained on test case: %s", tc));
        }
    }

    /**
     * Test that the {@link RhIdentity} is correctly extracted from a security
     * context.
     */
    @Test
    void testExtractRhIdentity() {
        // Mock the security context.
        final SecurityContext mockedSecurityContext = Mockito.mock(SecurityContext.class);

        // Create a RhIdentity principal and assign it to the mocked security
        // context.
        final RhIdentity identity = Mockito.mock(RhIdentity.class);
        Mockito.when(identity.getName()).thenReturn("Red Hat user");

        final ConsolePrincipal<?> principal = new RhIdPrincipal(identity);
        Mockito.when(mockedSecurityContext.getUserPrincipal()).thenReturn(principal);

        // Call the function under test.
        final RhIdentity result = this.kesselAuthorization.extractRhIdentity(mockedSecurityContext);

        // Assert that the objects are the same. Just by checking the object's
        // reference we can be sure that our stubbed principal above is the
        // one that was extracted.
        Assertions.assertEquals(
            identity,
            result,
            "the extracted identity object was not the same"
        );
    }

    /**
     * Test that when a "non-console" principal is extracted from the security
     * context, an exception is raised.
     */
    @Test
    void testExtractRhIdentityNoConsolePrincipalThrowsException() {
        // Mock the security context.
        final SecurityContext mockedSecurityContext = Mockito.mock(SecurityContext.class);

        // Mock a generic principal and make the context return it when asked
        // for it.
        final Principal mockedPrincipal = Mockito.mock(Principal.class);
        Mockito.when(mockedSecurityContext.getUserPrincipal()).thenReturn(Mockito.mock(Principal.class));

        // Call the function under test.
        final IllegalStateException e = Assertions.assertThrows(
            IllegalStateException.class,
            () -> this.kesselAuthorization.extractRhIdentity(mockedSecurityContext)
        );

        // Assert that the correct exception has been thrown.
        Assertions.assertEquals(
            String.format("unable to extract RH Identity object from principal. Expected \"Console Principal\" object type, got \"%s\"", mockedPrincipal.getClass().getName()),
            e.getMessage(),
            "unexpected exception message"
        );
    }

    /**
     * Test that a "non-RhIdentity" identity inside a principal raises an
     * exception.
     */
    @Test
    void testExtractRhIdentityNoSupportedIdentityThrowsException() {
        // Mock the security context.
        final SecurityContext mockedSecurityContext = Mockito.mock(SecurityContext.class);

        // Mock an unexpected identity which should trigger an exception.
        final TurnpikeSamlIdentity turnpikeSamlIdentity = new TurnpikeSamlIdentity();
        turnpikeSamlIdentity.associate = new TurnpikeSamlIdentity.Associate();
        turnpikeSamlIdentity.associate.email = "example@redhat.com";
        turnpikeSamlIdentity.type = "turnpike";

        // Make the identity part of the principal.
        final ConsolePrincipal<?> turnpikePrincipal = new TurnpikePrincipal(turnpikeSamlIdentity);
        Mockito.when(mockedSecurityContext.getUserPrincipal()).thenReturn(turnpikePrincipal);

        // Call the function under test.
        final IllegalStateException e = Assertions.assertThrows(
            IllegalStateException.class,
            () -> this.kesselAuthorization.extractRhIdentity(mockedSecurityContext)
        );

        // Assert that the correct exception has been thrown.
        Assertions.assertEquals(
            String.format("unable to extract RH Identity object from principal. Expected \"RhIdentity\" object type, got \"%s\"", turnpikeSamlIdentity.getClass().getName()),
            e.getMessage(),
            "unexpected exception message"
        );
    }

    /**
     * Tests that the function under test correctly extracts the subject's
     * type from its identity object.
     */
    @Test
    void testExtractSubjectTypeFromRhIdentity() {
        Assertions.assertEquals(KesselAuthorization.KESSEL_IDENTITY_SUBJECT_SERVICE_ACCOUNT, this.kesselAuthorization.extractSubjectTypeFromRhIdentity(new RhServiceAccountIdentity()));
        Assertions.assertEquals(KesselAuthorization.KESSEL_IDENTITY_SUBJECT_USER, this.kesselAuthorization.extractSubjectTypeFromRhIdentity(new RhUserIdentity()));
    }
}
