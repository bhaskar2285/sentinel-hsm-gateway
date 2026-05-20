package com.isc.sentinel.spi;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class HsmNodeRef {
    Long id;
    HsmVendor vendor;
    String host;
    int port;
    int weight;
    String direction;  // OUTBOUND | INBOUND
}
