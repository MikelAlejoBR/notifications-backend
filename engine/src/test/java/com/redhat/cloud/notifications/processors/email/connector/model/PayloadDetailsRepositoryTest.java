package com.redhat.cloud.notifications.processors.email.connector.model;

import com.redhat.cloud.notifications.TestLifecycleManager;
import com.redhat.cloud.notifications.db.ResourceHelpers;
import com.redhat.cloud.notifications.db.repositories.PayloadDetailsRepository;
import com.redhat.cloud.notifications.models.Application;
import com.redhat.cloud.notifications.models.Bundle;
import com.redhat.cloud.notifications.models.Event;
import com.redhat.cloud.notifications.models.EventType;
import com.redhat.cloud.notifications.processors.payload.PayloadDetails;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.UUID;

@QuarkusTest
@QuarkusTestResource(TestLifecycleManager.class)
public class PayloadDetailsRepositoryTest {
    @Inject
    EntityManager entityManager;

    @Inject
    PayloadDetailsRepository payloadDetailsRepository;

    @Inject
    ResourceHelpers resourceHelpers;

    /**
     * Tests that the payload details can be properly saved in the database and
     * then fetched from it.
     */
    @Test
    @Transactional
    void testSaveFetchEmailDetails() {
        // Prepare the test event.
        final Bundle bundle = this.resourceHelpers.createBundle("test-sfd-details");
        final Application application = this.resourceHelpers.createApp(bundle.getId(), "test-sfd-payload-details");
        final EventType eventType = this.resourceHelpers.createEventType(application.getId(), "test-sfd-payload-details");

        final Event event = new Event();
        event.setId(UUID.randomUUID());
        event.setEventType(eventType);

        final Event createdEvent = this.resourceHelpers.createEvent(event);

        // Create the test object.
        final JsonObject payloadContents = new JsonObject();
        payloadContents.put("hello", "world");

        final PayloadDetails payloadDetails = new PayloadDetails(createdEvent, payloadContents);

        // Store it in the database.
        this.payloadDetailsRepository.save(payloadDetails);
        this.entityManager.flush();

        // Fetch it and make sure that the data is correct.
        Assertions.assertEquals(1L, (Long) this.entityManager.createQuery("SELECT COUNT(*) FROM PayloadDetails").getSingleResult(), "a payload should have been stored in the database");

        final Optional<PayloadDetails> payloadDetailsOptional = this.payloadDetailsRepository.findById(payloadDetails.getId());

        if (payloadDetailsOptional.isEmpty()) {
            Assertions.fail("no results were returned when attempting to fetch a payload's details and a valid payload ID was specified");
        }

        final PayloadDetails fetchedPayloadDetails = payloadDetailsOptional.get();

        // Assert that the object got properly created.
        Assertions.assertEquals(payloadDetails.getId(), fetchedPayloadDetails.getId(), "the fetched payload ID is incorrect");
        Assertions.assertEquals(payloadDetails.getEventId(), fetchedPayloadDetails.getEventId(), "the event ID is incorrect");
        Assertions.assertEquals(payloadDetails.getContents(), fetchedPayloadDetails.getContents(), "the fetched payload is incorrect");

        // Delete the event from the database. Due to the "CASCADE DELETE"
        // statement for the payload's table, the database should have deleted
        // the payload too.
        this.entityManager.remove(event);
        this.entityManager.flush();
        this.entityManager.clear();

        // Assert that the object got properly deleted.
        Assertions.assertEquals(0L, (Long) this.entityManager.createQuery("SELECT COUNT(*) FROM PayloadDetails").getSingleResult(), "the database should not contain any payloads left after using the delete function from the repository");

        final PayloadDetails objectAfterDelete = this.entityManager.find(PayloadDetails.class, fetchedPayloadDetails.getId());

        Assertions.assertNull(objectAfterDelete);
    }
}
