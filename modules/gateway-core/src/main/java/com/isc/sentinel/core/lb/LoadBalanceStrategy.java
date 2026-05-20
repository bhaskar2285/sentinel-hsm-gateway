package com.isc.sentinel.core.lb;

public enum LoadBalanceStrategy {
    ROUND_ROBIN,
    WEIGHTED,
    LEAST_CONN,
    STICKY_KEY
}
