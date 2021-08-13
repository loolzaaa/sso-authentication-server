package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.controllers.AccessController;

@RequiredArgsConstructor
@ManagedResource
@Component
public class RFIDKeyMBean {

    private final AccessController accessController;

    @ManagedAttribute
    public String getKey() {
        return accessController.getKEY();
    }

    @ManagedAttribute
    public void setKey(String key) {
        accessController.setKEY(key);
    }
}
