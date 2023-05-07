package ru.loolzaaa.authserver.repositories;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import ru.loolzaaa.authserver.model.Webhook;
import ru.loolzaaa.authserver.webhook.WebhookEvent;

import java.util.List;

@Repository
public interface WebhookRepository extends CrudRepository<Webhook, Long> {
    List<Webhook> findByEventAndEnabledIsTrue(WebhookEvent event);
}
