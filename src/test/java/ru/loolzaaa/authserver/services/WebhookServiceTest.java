package ru.loolzaaa.authserver.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.loolzaaa.authserver.model.Webhook;
import ru.loolzaaa.authserver.repositories.WebhookRepository;
import ru.loolzaaa.authserver.webhook.WebhookEvent;

import java.util.Collections;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
@WireMockTest(httpPort = 8787)
class WebhookServiceTest {

    @Mock
    WebhookRepository webhookRepository;

    ObjectMapper mapper = new ObjectMapper();

    WebhookService webhookService;

    @BeforeEach
    void setUp() {
        webhookService = new WebhookService(mapper, webhookRepository);
    }

    @Test
    void shouldDoNothingIfThereIsNoWebhooks() {
        given(webhookRepository.findByEventAndEnabledIsTrue(any())).willReturn(Collections.emptyList());

        assertDoesNotThrow(() -> webhookService.fireEvent(null, null));
    }

    @ParameterizedTest
    @ValueSource(ints = {300, 200, 400, 999})
    void successfullyFireWebhookEvent(int statusCode) {
        final String LOGIN = "LOGIN";
        final String ID = "ID";
        final String SECRET = "SECRET";
        final String URL = "http://localhost:8787/app";
        final Webhook webhook = new Webhook();
        webhook.setEvent(WebhookEvent.DELETE_USER);
        webhook.setId(ID);
        webhook.setSecret(SECRET);
        webhook.setUrl(URL);
        final String jsonAnswer = String.format("{\"id\":\"%s\",\"message\":\"OK\"}", ID);
        given(webhookRepository.findByEventAndEnabledIsTrue(any())).willReturn(List.of(webhook));

        stubFor(post(urlEqualTo("/app/sso/webhook/" + ID))
                .withHeader("X-SSO-Signature", matching("sha256=.+"))
                .withHeader("Content-Type", containing("application/json"))
                .withRequestBody(equalToJson(String.format("{\"event\":\"DELETE_USER\",\"login\":\"%s\"}", LOGIN)))
                .willReturn(aResponse()
                        .withStatus(statusCode)
                        .withHeader("Content-Type", "application/json")
                        .withBody(jsonAnswer)));

        assertDoesNotThrow(() -> webhookService.fireEvent(WebhookEvent.DELETE_USER, LOGIN));
    }

    @Test
    void successfullyCatchWebhookError() {
        final String LOGIN = "LOGIN";
        final String ID = "ID";
        final String SECRET = "SECRET";
        final String URL = "http://localhost:8787/app";
        final Webhook webhook = new Webhook();
        webhook.setEvent(WebhookEvent.DELETE_USER);
        webhook.setId(ID);
        webhook.setSecret(SECRET);
        webhook.setUrl(URL);
        given(webhookRepository.findByEventAndEnabledIsTrue(any())).willReturn(List.of(webhook));

        stubFor(post(urlEqualTo("/app/sso/webhook/" + ID))
                .withHeader("X-SSO-Signature", matching("sha256=.+"))
                .withHeader("Content-Type", containing("application/json"))
                .withRequestBody(equalToJson(String.format("{\"event\":\"DELETE_USER\",\"login\":\"%s\"}", LOGIN)))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")));

        assertDoesNotThrow(() -> webhookService.fireEvent(WebhookEvent.DELETE_USER, LOGIN));
    }
}