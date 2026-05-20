package com.isc.sentinel.core.dispatch;

import com.isc.sentinel.core.audit.AuditService;
import com.isc.sentinel.core.lb.PoolRouter;
import com.isc.sentinel.spi.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class CommandDispatcher {

    private final Map<HsmVendor, HsmVendorAdapter> adapters;
    private final PoolRouter router;
    private final AuditService audit;

    public CommandDispatcher(List<HsmVendorAdapter> adapterList, PoolRouter router, AuditService audit) {
        this.adapters = adapterList.stream().collect(
            java.util.stream.Collectors.toMap(HsmVendorAdapter::vendor, a -> a));
        this.router = router;
        this.audit = audit;
    }

    public GatewayResponse dispatch(GatewayCommand cmd) {
        HsmVendor vendor = cmd.getVendorHint() != null ? cmd.getVendorHint() : HsmVendor.THALES;
        HsmVendorAdapter adapter = adapters.get(vendor);
        if (adapter == null || !adapter.supports(cmd.getOp())) {
            return errResp(cmd, vendor, "NS", "Op not supported by vendor " + vendor);
        }

        var nodeOpt = router.route(vendor, cmd.getKeyId());
        if (nodeOpt.isEmpty()) {
            return errResp(cmd, vendor, "NN", "No healthy HSM node available for " + vendor);
        }
        HsmNodeRef node = nodeOpt.get();

        String traceId = cmd.getTraceId() != null ? cmd.getTraceId() : UUID.randomUUID().toString();
        long t0 = System.currentTimeMillis();
        GatewayResponse resp = adapter.execute(cmd, node);
        audit.record(cmd, resp, node, traceId);
        log.info("dispatch op={} vendor={} node={} status={} latencyMs={}",
                 cmd.getOp(), vendor, node.getId(), resp.getStatus(), System.currentTimeMillis() - t0);
        return resp;
    }

    private GatewayResponse errResp(GatewayCommand cmd, HsmVendor vendor, String code, String text) {
        return GatewayResponse.builder()
            .op(cmd.getOp())
            .vendor(vendor)
            .status("ERROR")
            .errCode(code)
            .errText(text)
            .result(Map.of())
            .build();
    }
}
