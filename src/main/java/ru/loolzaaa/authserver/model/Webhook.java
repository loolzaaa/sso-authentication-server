package ru.loolzaaa.authserver.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
import ru.loolzaaa.authserver.webhook.WebhookEvent;

import java.util.Objects;

@Getter
@Setter
@Table("webhooks")
public class Webhook {
    @Id
    private String id;
    private WebhookEvent event;
    private String secret;
    private String url;
    private boolean enabled;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Webhook webhook = (Webhook) o;
        return id.equals(webhook.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
