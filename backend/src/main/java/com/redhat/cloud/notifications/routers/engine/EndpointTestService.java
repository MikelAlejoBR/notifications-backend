package com.redhat.cloud.notifications.routers.engine;

import com.redhat.cloud.notifications.routers.endpoints.EndpointTestRequest;
import com.redhat.cloud.notifications.routers.sources.SourcesXRHIDHeaderFactory;
import org.eclipse.microprofile.faulttolerance.Retry;
import org.eclipse.microprofile.rest.client.annotation.RegisterClientHeaders;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import javax.ws.rs.POST;
import javax.ws.rs.Path;

@RegisterClientHeaders(SourcesXRHIDHeaderFactory.class)
@RegisterRestClient(configKey = "internal-endpoint-test")
public interface EndpointTestService {

    /**
     * Sends a request to the engine to test the provided endpoint. This
     * happens when the client wants to test their integration with a test
     * event.
     * @param endpointTestRequest the payload of the request.
     */
    @Path("/internal/endpoints/test")
    @POST
    @Retry(maxRetries = 3)
    void testEndpoint(EndpointTestRequest endpointTestRequest);
}
