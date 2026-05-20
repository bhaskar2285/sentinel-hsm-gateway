package com.isc.sentinel.vendor.thales.transport;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;

import java.net.InetSocketAddress;
import java.net.Socket;

@Slf4j
public class ThalesSocketFactory extends BasePooledObjectFactory<Socket> {

    private final String host;
    private final int port;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    public ThalesSocketFactory(String host, int port, int connectTimeoutMs, int readTimeoutMs) {
        this.host = host;
        this.port = port;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
    }

    @Override
    public Socket create() throws Exception {
        Socket s = new Socket();
        s.setTcpNoDelay(true);
        s.setSoTimeout(readTimeoutMs);
        s.connect(new InetSocketAddress(host, port), connectTimeoutMs);
        log.debug("Thales socket open {}:{}", host, port);
        return s;
    }

    @Override
    public PooledObject<Socket> wrap(Socket s) {
        return new DefaultPooledObject<>(s);
    }

    @Override
    public void destroyObject(PooledObject<Socket> p) {
        Socket s = p.getObject();
        if (s != null && !s.isClosed()) {
            try { s.close(); } catch (Exception e) { log.warn("close error", e); }
        }
    }

    @Override
    public boolean validateObject(PooledObject<Socket> p) {
        Socket s = p.getObject();
        return s != null && s.isConnected() && !s.isClosed();
    }
}
