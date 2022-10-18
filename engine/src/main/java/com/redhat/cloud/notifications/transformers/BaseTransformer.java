package com.redhat.cloud.notifications.transformers;

import com.redhat.cloud.notifications.ingress.Action;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import javax.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.stream.Collectors;

@ApplicationScoped
public class BaseTransformer {

    /**
     * Transforms the given action into a {@link JsonObject}.
     * @param action the {@link Action} to transform.
     * @return a {@link JsonObject} containing the given action.
     */
    public JsonObject toJsonObject(final Action action) {
        JsonObject message = new JsonObject();

        message.put("account_id", action.getAccountId());
        message.put("application", action.getApplication());
        message.put("bundle", action.getBundle());
        message.put("context", JsonObject.mapFrom(action.getContext()));
        message.put("event_type", action.getEventType());
        message.put(
            "events",
            new JsonArray(
                action.getEvents().stream().map(
                    event -> Map.of(
                        "metadata", JsonObject.mapFrom(event.getMetadata()),
                        "payload", JsonObject.mapFrom(event.getPayload())
                    )
                ).collect(Collectors.toList())
            )
        );
        message.put("org_id", action.getOrgId());
        message.put("timestamp", action.getTimestamp().toString());

        return message;
    }

}
