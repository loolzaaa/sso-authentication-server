package ru.loolzaaa.authserver.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import ru.loolzaaa.authserver.dto.WebhookPayload;
import ru.loolzaaa.authserver.model.Webhook;
import ru.loolzaaa.authserver.repositories.WebhookRepository;
import ru.loolzaaa.authserver.webhook.WebhookEvent;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Log4j2
@Service
public class WebhookService {

    private static final String ALGORITHM = "HmacSHA256";

    private static final String SIGNATURE_HEADER_NAME = "X-SSO-Signature";

    private final ObjectMapper mapper;

    private final WebhookRepository webhookRepository;

    private final RestTemplate restTemplate;

    public WebhookService(ObjectMapper mapper, WebhookRepository webhookRepository) {
        this.mapper = mapper;
        this.webhookRepository = webhookRepository;

        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new CustomErrorHandler());
        this.restTemplate = restTemplate;
    }

    public void fireEvent(WebhookEvent event, String login) {
        List<Webhook> webhooks = webhookRepository.findByEventAndEnabledIsTrue(event);
        if (webhooks.size() == 0) {
            return;
        }
        for (Webhook webhook : webhooks) {
            try {
                log.info("Process {} webhook for {} event", webhook.getId(), webhook.getEvent());

                WebhookPayload payload = new WebhookPayload();
                payload.setEvent(event);
                payload.setLogin(login);
                byte[] payloadAsBytes = mapper.writeValueAsBytes(payload);

                SecretKeySpec secretKeySpec = new SecretKeySpec(webhook.getSecret().getBytes(StandardCharsets.UTF_8), ALGORITHM);
                Mac mac = Mac.getInstance(ALGORITHM);
                mac.init(secretKeySpec);
                String signature = "sha256=" + bytesToHex(mac.doFinal(payloadAsBytes));

                final String url = webhook.getUrl() + "/sso/webhook/" + webhook.getId();

                HttpHeaders headers = new HttpHeaders();
                headers.add(SIGNATURE_HEADER_NAME, signature);

                HttpEntity<WebhookPayload> request = new HttpEntity<>(payload, headers);

                ResponseEntity<WebhookResult> response = restTemplate.postForEntity(url, request, WebhookResult.class);
                WebhookResult result = response.getBody();
                if (result == null) {
                    throw new NullPointerException("Webhook process answer is null");
                }

                if (response.getStatusCodeValue() == 200) {
                    log.info("Webhook [{}] successfully completed: {}", webhook.getId(), result);
                } else {
                    log.warn("Webhook [{}] process error: {}", webhook.getId(), result);
                }
            } catch (Exception e) {
                log.error("Process {} webhook [{}] error: {}", webhook.getId(), webhook.getEvent(), e.getMessage());
            }
        }
    }

    private String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    @Getter
    @Setter
    @ToString
    private static class WebhookResult {
        private String id;
        private String message;
    }

    private static class CustomErrorHandler extends DefaultResponseErrorHandler {
        @Override
        protected boolean hasError(HttpStatus statusCode) {
            return false;
        }

        @Override
        protected boolean hasError(int unknownStatusCode) {
            return false;
        }
    }
}
