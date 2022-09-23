package ru.loolzaaa.authserver.config.security.bean;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.loolzaaa.authserver.controllers.AccessController;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RFIDKeyMBeanTest {

    @Mock
    AccessController accessController;

    RFIDKeyMBean rfidKeyMBean;

    @BeforeEach
    void setUp() {
        rfidKeyMBean = new RFIDKeyMBean(accessController);
    }

    @Test
    void shouldInvokeGetterOfAccessController() {
        final String KEY = "111";
        when(accessController.getKEY()).thenReturn(KEY);

        String key = rfidKeyMBean.getKey();

        assertEquals(key, KEY);
        verify(accessController).getKEY();
    }

    @Test
    void shouldInvokeSetterOfAccessController() {
        final String KEY = "111";
        doNothing().when(accessController).setKEY(anyString());
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);

        rfidKeyMBean.setKey(KEY);

        verify(accessController).setKEY(keyCaptor.capture());
        assertEquals(keyCaptor.getValue(), KEY);
    }
}