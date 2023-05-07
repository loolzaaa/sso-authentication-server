package ru.loolzaaa.authserver.dto;

import lombok.Getter;
import lombok.Setter;
import ru.loolzaaa.authserver.webhook.WebhookEvent;

@Getter
@Setter
public class WebhookPayload {
    private WebhookEvent event;
    private String login;
}
