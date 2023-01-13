package com.redhat.cloud.notifications.routers;

import com.redhat.cloud.notifications.events.FromCamelHistoryFiller;
import com.redhat.cloud.notifications.ingress.Action;
import com.redhat.cloud.notifications.models.event.TestEventHelper;
import com.redhat.cloud.notifications.routers.endpoints.EndpointTestRequest;
import org.eclipse.microprofile.reactive.messaging.Channel;
import org.eclipse.microprofile.reactive.messaging.Emitter;

import javax.inject.Inject;
import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import static com.redhat.cloud.notifications.Constants.API_INTERNAL;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Path(API_INTERNAL + "/endpoints")
public class EndpointTestResource {

    @Channel(FromCamelHistoryFiller.EGRESS_CHANNEL)
    @Inject
    Emitter<Action> eventEmitter;

    /**
     * Creates a "endpoint integration test" action and sends it to the ingress
     * Kafka channel, based on the received payload.
     * @param endpointTestRequest the payload to create the test event from.
     */
    @Consumes(APPLICATION_JSON)
    @Path("/test")
    @POST
    public Response testEndpoint(@Valid final EndpointTestRequest endpointTestRequest) {
        final Action testAction = TestEventHelper.createTestAction(
            endpointTestRequest.endpointUuid,
            endpointTestRequest.orgId
        );

        this.eventEmitter.send(testAction);

        return Response.noContent().build();
    }
}
