package com.redhat.cloud.notifications.exports;

import com.redhat.cloud.event.apps.exportservice.v1.ExportRequest;
import com.redhat.cloud.event.apps.exportservice.v1.ExportRequestClass;
import com.redhat.cloud.event.apps.exportservice.v1.Format;
import com.redhat.cloud.event.parser.ConsoleCloudEventParser;
import com.redhat.cloud.event.parser.GenericConsoleCloudEvent;
import com.redhat.cloud.notifications.Constants;
import com.redhat.cloud.notifications.MicrometerAssertionHelper;
import com.redhat.cloud.notifications.MockServerLifecycleManager;
import com.redhat.cloud.notifications.TestLifecycleManager;
import com.redhat.cloud.notifications.db.repositories.EventRepository;
import com.redhat.cloud.notifications.exports.transformers.TransformersHelpers;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.mockito.InjectMock;
import io.smallrye.reactive.messaging.providers.connectors.InMemoryConnector;
import io.smallrye.reactive.messaging.providers.connectors.InMemorySource;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.MediaType;

import javax.enterprise.inject.Any;
import javax.inject.Inject;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.redhat.cloud.notifications.TestConstants.DEFAULT_ORG_ID;
import static com.redhat.cloud.notifications.exports.ExportEventListener.EXPORT_CHANNEL;
import static com.redhat.cloud.notifications.exports.ExportEventListener.FILTER_DATE_FROM;
import static com.redhat.cloud.notifications.exports.ExportEventListener.FILTER_DATE_TO;
import static org.awaitility.Awaitility.await;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@QuarkusTest
@QuarkusTestResource(TestLifecycleManager.class)
public class ExportEventListenerTest {

    private static final LocalDate TODAY = LocalDate.now(ZoneOffset.UTC);

    @ConfigProperty(name = "export-service.psk")
    String exportServicePsk;

    @InjectMock
    EventRepository eventRepository;

    @Inject
    ExportEventListener exportEventListener;

    @Any
    @Inject
    InMemoryConnector inMemoryConnector;

    @Inject
    MicrometerAssertionHelper micrometerAssertionHelper;

    /**
     * Sets up the routes for the Mock Server.
     */
    @BeforeEach
    void setUpMockServerRoutes() {
        final ClientAndServer mockServer = MockServerLifecycleManager.getClient();

        mockServer
            .when(request().withPath(".*/error"))
            .respond(response().withStatusCode(200));

        mockServer
            .when(request().withPath(".*/upload"))
            .respond(response().withStatusCode(200));
    }

    /**
     * Clears everything from the Mock Server.
     */
    @AfterEach
    void clearMockServer() {
        MockServerLifecycleManager.getClient().reset();
    }

    /**
     * Tests that when an export request is received with an invalid resource
     * type, then an error is sent to the export service.
     */
    @Test
    void testInvalidResourceTypeRaisesError() {
        // Save the counter values to assert the "errors count" change later.
        this.micrometerAssertionHelper.saveCounterValuesBeforeTest(ExportEventListener.EXPORTS_SERVICE_FAILURES_COUNTER);

        final InMemorySource<String> exportIn = this.inMemoryConnector.source(EXPORT_CHANNEL);

        // Generate an export request but set a resource type which we don't
        // support.
        final GenericConsoleCloudEvent<ExportRequest> cee = ExportEventTestHelper.createExportCloudEventFixture(Format.JSON);
        final ExportRequestClass data = cee.getData().getExportRequest();
        data.setResource("invalid-type");

        // Serialize the payload and send it to the Kafka topic.
        final ConsoleCloudEventParser consoleCloudEventParser = new ConsoleCloudEventParser();
        exportIn.send(consoleCloudEventParser.toJson(cee));

        // Wait until the handler sends an error to the export service.
        await()
            .atMost(Duration.ofSeconds(10))
            .until(() -> MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/error")).length != 0);

        // Assert that only one request was received.
        final HttpRequest[] requests = MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/error"));
        Assertions.assertEquals(1, requests.length, "unexpected number of requests received in the error endpoint");

        final HttpRequest request = requests[0];

        // Assert that the correct path was called.
        final String path = request.getPath().toString();

        final String expectedPath = String.format(
            "/app/export/v1/%s/%s/%s/error",
            ExportEventTestHelper.getExportCeUuid(),
            data.getApplication(),
            data.getUUID()
        );

        Assertions.assertEquals(expectedPath, path, "unexpected path parameters sent to the error endpoint");

        // Check the PSK.
        Assertions.assertEquals(request.getFirstHeader(Constants.X_RH_EXPORT_SERVICE_PSK), this.exportServicePsk, "unexpected PSK value received");

        final JsonObject body = new JsonObject(request.getBodyAsString());

        Assertions.assertEquals("400", body.getString("code"), "unexpected error code received in the error's body");
        Assertions.assertEquals("the specified resource type is unsupported by this application", body.getString("message"), "unexpected error message received in the error's body");

        // Assert that the errors counter was incremented.
        this.micrometerAssertionHelper.assertCounterIncrement(ExportEventListener.EXPORTS_SERVICE_FAILURES_COUNTER, 1);
    }

    /**
     * Tests that when an export request is received and the specified "from"
     * filter is non-parseable, an error is sent to the export service.
     */
    @Test
    void testNonParseableFromFilterRaisesError() {
        // Save the counter values to assert the "errors count" change later.
        this.micrometerAssertionHelper.saveCounterValuesBeforeTest(ExportEventListener.EXPORTS_SERVICE_FAILURES_COUNTER);

        final InMemorySource<String> exportIn = this.inMemoryConnector.source(EXPORT_CHANNEL);

        // Generate an export request but set a resource type which we don't
        // support.
        final GenericConsoleCloudEvent<ExportRequest> cee = ExportEventTestHelper.createExportCloudEventFixture(Format.JSON);
        final ExportRequestClass data = cee.getData().getExportRequest();
        data.setFilters(Map.of("from", "invalid-date"));

        // Serialize the payload and send it to the Kafka topic.
        final ConsoleCloudEventParser consoleCloudEventParser = new ConsoleCloudEventParser();
        exportIn.send(consoleCloudEventParser.toJson(cee));

        // Wait until the handler sends an error to the export service.
        await()
            .atMost(Duration.ofSeconds(10))
            .until(() -> MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/error")).length != 0);

        // Assert that only one request was received.
        final HttpRequest[] requests = MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/error"));
        Assertions.assertEquals(1, requests.length, "unexpected number of requests received in the error endpoint");

        final HttpRequest request = requests[0];

        // Assert that the correct path was called.
        final String path = request.getPath().toString();

        final String expectedPath = String.format(
            "/app/export/v1/%s/%s/%s/error",
            ExportEventTestHelper.getExportCeUuid(),
            data.getApplication(),
            data.getUUID()
        );

        Assertions.assertEquals(expectedPath, path, "unexpected path parameters sent to the error endpoint");

        // Check the PSK.
        Assertions.assertEquals(request.getFirstHeader(Constants.X_RH_EXPORT_SERVICE_PSK), this.exportServicePsk, "unexpected PSK value received");

        final JsonObject body = new JsonObject(request.getBodyAsString());

        Assertions.assertEquals("400", body.getString("code"), "unexpected error code received in the error's body");
        Assertions.assertEquals("unable to parse the 'from' date filter with the 'yyyy-mm-dd' format", body.getString("message"), "unexpected error message received in the error's body");

        // Assert that the errors counter was incremented.
        this.micrometerAssertionHelper.assertCounterIncrement(ExportEventListener.EXPORTS_SERVICE_FAILURES_COUNTER, 1);
    }

    /**
     * Tests that when an export request is received and the specified "to"
     * filter is non-parseable, an error is sent to the export service.
     */
    @Test
    void testNonParseableToFilterRaisesError() {
        // Save the counter values to assert the "errors count" change later.
        this.micrometerAssertionHelper.saveCounterValuesBeforeTest(ExportEventListener.EXPORTS_SERVICE_FAILURES_COUNTER);

        final InMemorySource<String> exportIn = this.inMemoryConnector.source(EXPORT_CHANNEL);

        // Generate an export request but set a resource type which we don't
        // support.
        final GenericConsoleCloudEvent<ExportRequest> cee = ExportEventTestHelper.createExportCloudEventFixture(Format.JSON);
        final ExportRequestClass data = cee.getData().getExportRequest();
        data.setFilters(Map.of("to", "invalid-date"));

        // Serialize the payload and send it to the Kafka topic.
        final ConsoleCloudEventParser consoleCloudEventParser = new ConsoleCloudEventParser();
        exportIn.send(consoleCloudEventParser.toJson(cee));

        // Wait until the handler sends an error to the export service.
        await()
            .atMost(Duration.ofSeconds(10))
            .until(() -> MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/error")).length != 0);

        // Assert that only one request was received.
        final HttpRequest[] requests = MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/error"));
        Assertions.assertEquals(1, requests.length, "unexpected number of requests received in the error endpoint");

        final HttpRequest request = requests[0];

        // Assert that the correct path was called.
        final String path = request.getPath().toString();

        final String expectedPath = String.format(
            "/app/export/v1/%s/%s/%s/error",
            ExportEventTestHelper.getExportCeUuid(),
            data.getApplication(),
            data.getUUID()
        );

        Assertions.assertEquals(expectedPath, path, "unexpected path parameters sent to the error endpoint");

        // Check the PSK.
        Assertions.assertEquals(request.getFirstHeader(Constants.X_RH_EXPORT_SERVICE_PSK), this.exportServicePsk, "unexpected PSK value received");

        final JsonObject body = new JsonObject(request.getBodyAsString());

        Assertions.assertEquals("400", body.getString("code"), "unexpected error code received in the error's body");
        Assertions.assertEquals("unable to parse the 'to' date filter with the 'yyyy-mm-dd' format", body.getString("message"), "unexpected error message received in the error's body");

        // Assert that the errors counter was incremented.
        this.micrometerAssertionHelper.assertCounterIncrement(ExportEventListener.EXPORTS_SERVICE_FAILURES_COUNTER, 1);
    }

    /**
     * Tests that when an export request is received and the specified filters
     * filter are invalid, an error is sent to the export service.
     */
    @Test
    void testInvalidFiltersRaisesError() {
        // Save the counter values to assert the "errors count" change later.
        this.micrometerAssertionHelper.saveCounterValuesBeforeTest(ExportEventListener.EXPORTS_SERVICE_FAILURES_COUNTER);

        record TestCase(LocalDate from, LocalDate to, String expectedErrorMessage) { }

        final List<TestCase> testCases = new ArrayList<>();

        final LocalDate today = LocalDate.now(ZoneOffset.UTC);

        // "From" date in the future.
        testCases.add(
            new TestCase(
                today.plusDays(1),
                null,
                "invalid 'from' filter date specified: the specified date is in the future"
            )
        );

        // "From" date is older than a month.
        testCases.add(
            new TestCase(
                today.minusMonths(1).minusDays(1),
                null,
                "invalid 'from' filter date specified: the specified date is older than a month"
            )
        );

        // "From" date is after the "to" date.
        testCases.add(
            new TestCase(
                today.minusDays(5),
                today.minusDays(10),
                "the 'to' date cannot be lower than the 'from' date"
            )
        );

        // "To" date is in the future.
        testCases.add(
            new TestCase(
                null,
                today.plusDays(1),
                "invalid 'to' filter date specified: the specified date is in the future"
            )
        );

        // "To" date is older than a month.
        testCases.add(
            new TestCase(
                null,
                today.minusMonths(1).minusDays(1),
                "invalid 'to' filter date specified: the specified date is older than a month"
            )
        );

        final InMemorySource<String> exportIn = this.inMemoryConnector.source(EXPORT_CHANNEL);

        for (final TestCase testCase : testCases) {
            this.setUpMockServerRoutes();

            // Generate an export request but set a resource type which we don't
            // support.
            final GenericConsoleCloudEvent<ExportRequest> cee = ExportEventTestHelper.createExportCloudEventFixture(Format.JSON);
            final ExportRequestClass data = cee.getData().getExportRequest();
            final Map<String, Object> filters = data.getFilters();
            // Clear the filters to start fresh with them.
            filters.clear();

            if (testCase.from != null) {
                filters.put(ExportEventListener.FILTER_DATE_FROM, testCase.from.toString());
            }

            if (testCase.to != null) {
                filters.put(ExportEventListener.FILTER_DATE_TO, testCase.to.toString());
            }

            // Serialize the payload and send it to the Kafka topic.
            final ConsoleCloudEventParser consoleCloudEventParser = new ConsoleCloudEventParser();
            exportIn.send(consoleCloudEventParser.toJson(cee));

            // Wait until the handler sends an error to the export service.
            await()
                .atMost(Duration.ofSeconds(10))
                .until(() -> MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/error")).length != 0);

            // Assert that only one request was received.
            final HttpRequest[] requests = MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/error"));
            Assertions.assertEquals(1, requests.length, "unexpected number of requests received in the error endpoint");

            final HttpRequest request = requests[0];

            // Assert that the correct path was called.
            final String path = request.getPath().toString();

            final String expectedPath = String.format(
                "/app/export/v1/%s/%s/%s/error",
                ExportEventTestHelper.getExportCeUuid(),
                data.getApplication(),
                data.getUUID()
            );

            Assertions.assertEquals(expectedPath, path, "unexpected path parameters sent to the error endpoint");

            // Check the PSK.
            Assertions.assertEquals(request.getFirstHeader(Constants.X_RH_EXPORT_SERVICE_PSK), this.exportServicePsk, "unexpected PSK value received");

            final JsonObject body = new JsonObject(request.getBodyAsString());

            Assertions.assertEquals("400", body.getString("code"), "unexpected error code received in the error's body");
            Assertions.assertEquals(testCase.expectedErrorMessage, body.getString("message"), String.format("unexpected error message received in the error's body. Test case: %s", testCase));

            // Clear the recorded requests to not mess up with the next
            // iteration.
            this.clearMockServer();
        }

        // Assert that the errors counter was incremented.
        this.micrometerAssertionHelper.assertCounterIncrement(ExportEventListener.EXPORTS_SERVICE_FAILURES_COUNTER, testCases.size());
    }

    /**
     * Tests that when a valid JSON export request is received, then a valid
     * request is sent to the export service, containing the expected body.
     */
    @Test
    void testExportJSON() throws IOException, URISyntaxException {
        // Save the counter values to assert the "successes count" change later.
        this.micrometerAssertionHelper.saveCounterValuesBeforeTest(ExportEventListener.EXPORTS_SERVICE_SUCCESSES_COUNTER);

        final InMemorySource<String> exportIn = this.inMemoryConnector.source(EXPORT_CHANNEL);

        // Generate an export request but set a resource type which we don't
        // support.
        final GenericConsoleCloudEvent<ExportRequest> cee = ExportEventTestHelper.createExportCloudEventFixture(Format.JSON);
        final ExportRequestClass data = cee.getData().getExportRequest();

        // Serialize the payload and send it to the Kafka topic.
        final ConsoleCloudEventParser consoleCloudEventParser = new ConsoleCloudEventParser();

        // Return fixture events when the repository is called.
        Mockito.when(this.eventRepository.findEventsToExport(Mockito.eq(DEFAULT_ORG_ID), Mockito.any(), Mockito.any())).thenReturn(TransformersHelpers.getFixtureEvents());

        // Send the JSON payload but replace the "json" format with an
        // unsupported one.
        exportIn.send(consoleCloudEventParser.toJson(cee));

        // Wait until the handler sends an error to the export service.
        await()
            .atMost(Duration.ofSeconds(10))
            .until(() -> MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/upload")).length != 0);

        // Assert that only one request was received.
        final HttpRequest[] requests = MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/upload"));
        Assertions.assertEquals(1, requests.length, "unexpected number of requests received in the upload endpoint");

        final HttpRequest request = requests[0];

        // Assert that the correct path was called.
        final String path = request.getPath().toString();

        final String expectedPath = String.format(
            "/app/export/v1/%s/%s/%s/upload",
            ExportEventTestHelper.getExportCeUuid(),
            data.getApplication(),
            data.getUUID()
        );

        Assertions.assertEquals(expectedPath, path, "unexpected path parameters sent to the upload endpoint");

        Assertions.assertEquals(
            request.getFirstHeader("Content-Type"),
            MediaType.APPLICATION_JSON.toString(),
            "unexpected content type header sent to the export service"
        );

        // Check the PSK.
        Assertions.assertEquals(request.getFirstHeader(Constants.X_RH_EXPORT_SERVICE_PSK), this.exportServicePsk, "unexpected PSK value received");

        // Load the expected body output.
        final URL jsonResourceUrl = this.getClass().getResource("/resultstransformers/event/expectedResult.json");
        Assertions.assertNotNull(jsonResourceUrl, "the JSON file with the expected result was not located");

        final String expectedContents = Files.readString(Path.of(jsonResourceUrl.toURI()));

        // Assert that both the expected contents and the result are valid JSON
        // objects.
        final JsonArray expectedJson = new JsonArray(expectedContents);
        final JsonArray resultJson = new JsonArray(request.getBodyAsString());

        // Encode both prettily so that if an error occurs, it is easier to
        // spot where the problem is.
        Assertions.assertEquals(expectedJson.encodePrettily(), resultJson.encodePrettily(), "unexpected JSON body received");

        // Assert that the successes counter was incremented.
        this.micrometerAssertionHelper.assertCounterIncrement(ExportEventListener.EXPORTS_SERVICE_SUCCESSES_COUNTER, 1);
    }

    /**
     * Tests that when a valid CSV export request is received, then a valid
     * request is sent to the export service, containing the expected body.
     */
    @Test
    void testExportCSV() throws IOException, URISyntaxException {
        // Save the counter values to assert the "successes count" change later.
        this.micrometerAssertionHelper.saveCounterValuesBeforeTest(ExportEventListener.EXPORTS_SERVICE_SUCCESSES_COUNTER);

        final InMemorySource<String> exportIn = this.inMemoryConnector.source(EXPORT_CHANNEL);

        // Generate an export request but set a resource type which we don't
        // support.
        final GenericConsoleCloudEvent<ExportRequest> cee = ExportEventTestHelper.createExportCloudEventFixture(Format.JSON);
        final ExportRequestClass data = cee.getData().getExportRequest();
        data.setFormat(Format.CSV);

        // Serialize the payload and send it to the Kafka topic.
        final ConsoleCloudEventParser consoleCloudEventParser = new ConsoleCloudEventParser();

        // Return fixture events when the repository is called.
        Mockito.when(this.eventRepository.findEventsToExport(Mockito.eq(DEFAULT_ORG_ID), Mockito.any(), Mockito.any())).thenReturn(TransformersHelpers.getFixtureEvents());

        // Send the JSON payload but replace the "json" format with an
        // unsupported one.
        exportIn.send(consoleCloudEventParser.toJson(cee));

        // Wait until the handler sends an error to the export service.
        await()
            .atMost(Duration.ofSeconds(10))
            .until(() -> MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/upload")).length != 0);

        final HttpRequest[] requests = MockServerLifecycleManager.getClient().retrieveRecordedRequests(request().withPath(".*/upload"));
        Assertions.assertEquals(1, requests.length, "unexpected number of requests received in the upload endpoint");

        final HttpRequest request = requests[0];
        final String path = request.getPath().toString();

        final String expectedPath = String.format(
            "/app/export/v1/%s/%s/%s/upload",
            ExportEventTestHelper.getExportCeUuid(),
            data.getApplication(),
            data.getUUID()
        );

        Assertions.assertEquals(expectedPath, path, "unexpected path parameters sent to the upload endpoint");

        Assertions.assertEquals(
            request.getFirstHeader("Content-Type"),
            "text/csv",
            "unexpected content type header sent to the export service"
        );

        // Check the PSK.
        Assertions.assertEquals(request.getFirstHeader(Constants.X_RH_EXPORT_SERVICE_PSK), this.exportServicePsk, "unexpected PSK value received");

        // Load the expected body output.
        final URL csvResourceUrl = this.getClass().getResource("/resultstransformers/event/expectedResult.csv");
        Assertions.assertNotNull(csvResourceUrl, "the CSV file with the expected result was not located");

        final String expectedContents = Files.readString(Path.of(csvResourceUrl.toURI()));

        Assertions.assertEquals(expectedContents, request.getBodyAsString(), "unexpected CSV body received");

        // Assert that the successes counter was incremented.
        this.micrometerAssertionHelper.assertCounterIncrement(ExportEventListener.EXPORTS_SERVICE_SUCCESSES_COUNTER, 1);
    }

    /**
     * Tests that when no dates are provided the function under test does not
     * raise any exceptions.
     */
    @Test
    void testNoDate() {
        this.exportEventListener.extractDateFromFilter(new HashMap<>(), ExportEventListener.FILTER_DATE_FROM);
    }

    /**
     * Tests that when a proper date is provided in the filters map, it is
     * correctly extracted from the map.
     */
    @Test
    void testValidDate() {
        final Map<String, Object> filters = Map.of(
            ExportEventListener.FILTER_DATE_FROM,
            TODAY.toString()
        );

        final LocalDate result = this.exportEventListener.extractDateFromFilter(filters, FILTER_DATE_FROM);

        Assertions.assertEquals(TODAY, result, "the date was not correctly extracted from the map");
    }

    /**
     * Tests that "from" dates that are in the future cause an exception to
     * raise.
     */
    @Test
    void testInvalidDateFuture() {
        final Map<String, Object> filters = Map.of(
            ExportEventListener.FILTER_DATE_FROM,
            TODAY
                .plusDays(1)
                .toString()
        );

        final IllegalStateException exception = Assertions.assertThrows(
            IllegalStateException.class,
            () -> this.exportEventListener.extractDateFromFilter(filters, FILTER_DATE_FROM)
        );

        Assertions.assertEquals("the specified date is in the future", exception.getMessage(), "unexpected error message when extracting and validating a date from the future");
    }

    /**
     * Tests that "from" dates that are older than a month cause an exception
     * to raise.
     */
    @Test
    void testInvalidDateOlderMonth() {
        final Map<String, Object> filters = Map.of(
            ExportEventListener.FILTER_DATE_TO,
            TODAY
                .minusMonths(1)
                .minusDays(1)
                .toString()
        );

        final IllegalStateException exception = Assertions.assertThrows(
            IllegalStateException.class,
            () -> this.exportEventListener.extractDateFromFilter(filters, FILTER_DATE_TO)
        );

        Assertions.assertEquals("the specified date is older than a month", exception.getMessage(), "unexpected error message when extracting and validating a date older than a month");
    }

    /**
     * Tests that the function under test correctly extracts the {@link UUID}
     * from the subject.
     */
    @Test
    void testValidSubjectExtractUuid() {
        final UUID subjectUuid = UUID.randomUUID();
        final String validSubject = String.format("urn:redhat:subject:export-service:request:%s", subjectUuid);

        final UUID extractedUuid = this.exportEventListener.extractExportUuidFromSubject(validSubject);

        Assertions.assertEquals(subjectUuid, extractedUuid, "unexpected UUID extracted from the subject");
    }

    /**
     * Tests that the function under test throws an exception when an invalid
     * subject is received.
     */
    @Test
    void testInvalidSubjectExtractUuid() {
        final List<String> invalidSubjects = List.of(
            UUID.randomUUID().toString(),
            String.format("urn:redhat:subject:%s", UUID.randomUUID()),
            "random subject"
        );

        for (final String invalidSubject : invalidSubjects) {
            Assertions.assertThrows(
                IllegalStateException.class,
                () -> this.exportEventListener.extractExportUuidFromSubject(invalidSubject)
            );
        }
    }
}