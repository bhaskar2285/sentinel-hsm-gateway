package com.isc.sentinel.vendor.thales.transport;

import com.isc.sentinel.spi.HsmNodeRef;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-node socket pool registry. One pool per HsmNodeRef.
 * Send raw wire bytes (4-byte length-prefixed), receive raw response bytes (length-prefixed).
 */
@Slf4j
public class ThalesTransport {

    private final Map<Long, GenericObjectPool<Socket>> pools = new ConcurrentHashMap<>();
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int maxPerNode;
    private final boolean tls;
    private final boolean tlsInsecureSkipVerify;

    public ThalesTransport(int connectTimeoutMs, int readTimeoutMs, int maxPerNode) {
        this(connectTimeoutMs, readTimeoutMs, maxPerNode, false, false);
    }

    public ThalesTransport(int connectTimeoutMs, int readTimeoutMs, int maxPerNode,
                           boolean tls, boolean tlsInsecureSkipVerify) {
        this.connectTimeoutMs       = connectTimeoutMs;
        this.readTimeoutMs          = readTimeoutMs;
        this.maxPerNode             = maxPerNode;
        this.tls                    = tls;
        this.tlsInsecureSkipVerify  = tlsInsecureSkipVerify;
    }

    private GenericObjectPool<Socket> poolFor(HsmNodeRef node) {
        return pools.computeIfAbsent(node.getId(), id -> {
            var cfg = new GenericObjectPoolConfig<Socket>();
            cfg.setMaxTotal(maxPerNode);
            cfg.setMaxIdle(maxPerNode);
            cfg.setMinIdle(1);
            cfg.setTestOnBorrow(true);
            cfg.setTestWhileIdle(true);
            return new GenericObjectPool<>(
                new ThalesSocketFactory(node.getHost(), node.getPort(),
                    connectTimeoutMs, readTimeoutMs, tls, tlsInsecureSkipVerify),
                cfg);
        });
    }

    public byte[] roundTrip(HsmNodeRef node, byte[] wireRequest) throws IOException {
        GenericObjectPool<Socket> pool = poolFor(node);
        Socket s = null;
        boolean invalid = false;
        try {
            s = pool.borrowObject();
            OutputStream out = s.getOutputStream();
            DataInputStream in = new DataInputStream(s.getInputStream());

            out.write(wireRequest);
            out.flush();

            int len = in.readUnsignedShort();
            if (len <= 0 || len > 65535) {
                invalid = true;
                throw new IOException("invalid response length " + len);
            }
            byte[] body = new byte[len];
            in.readFully(body);
            return body;
        } catch (Exception e) {
            invalid = true;
            if (e instanceof IOException io) throw io;
            throw new IOException("HSM roundtrip failed", e);
        } finally {
            if (s != null) {
                try {
                    if (invalid) pool.invalidateObject(s);
                    else         pool.returnObject(s);
                } catch (Exception ignored) { /* pool close race */ }
            }
        }
    }

    public void shutdown() {
        pools.values().forEach(GenericObjectPool::close);
        pools.clear();
    }
}
