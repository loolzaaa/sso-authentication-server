package ru.loolzaaa.authserver.config.security.bean;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Component;
import ru.loolzaaa.authserver.controllers.AccessController;

@Log4j2
@RequiredArgsConstructor
@ManagedResource
@Component
public class RFIDKeyMBean {

    private final AccessController accessController;

    @ManagedAttribute
    public String getKey() {
        log.warn("RFID Key getter invoked!");
        return accessController.getRfidKEY();
    }

    @ManagedAttribute
    public void setKey(String key) {
        log.warn("RFID Key setter invoked!");
        accessController.setRfidKEY(key);
    }
}
