package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.controllers.AccessController;

@Slf4j
@RequiredArgsConstructor
@ManagedResource
@Component
public class RFIDKeyMBean {

    private final AccessController accessController;

    @ManagedAttribute
    public String getKey() {
        log.info("RFID Key getter invoked!");
        return accessController.getRfidKEY();
    }

    @ManagedAttribute
    public void setKey(String key) {
        log.info("RFID Key setter invoked!");
        accessController.setRfidKEY(key);
    }
}
