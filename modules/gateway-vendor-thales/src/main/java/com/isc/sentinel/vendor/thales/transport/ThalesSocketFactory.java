package com.isc.sentinel.vendor.thales.transport;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;

@Slf4j
public class ThalesSocketFactory extends BasePooledObjectFactory<Socket> {

    private final String host;
    private final int port;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final boolean tls;
    private final boolean tlsInsecureSkipVerify;

    public ThalesSocketFactory(String host, int port, int connectTimeoutMs, int readTimeoutMs) {
        this(host, port, connectTimeoutMs, readTimeoutMs, false, false);
    }

    public ThalesSocketFactory(String host, int port, int connectTimeoutMs, int readTimeoutMs,
                               boolean tls, boolean tlsInsecureSkipVerify) {
        this.host = host;
        this.port = port;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs    = readTimeoutMs;
        this.tls              = tls;
        this.tlsInsecureSkipVerify = tlsInsecureSkipVerify;
    }

    @Override
    public Socket create() throws Exception {
        Socket s;
        if (tls) {
            SSLSocketFactory factory = tlsInsecureSkipVerify
                ? insecureFactory()
                : (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket ssl = (SSLSocket) factory.createSocket();
            ssl.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            ssl.setSoTimeout(readTimeoutMs);
            ssl.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            ssl.startHandshake();
            s = ssl;
            log.debug("Thales TLS socket open {}:{} skipVerify={}", host, port, tlsInsecureSkipVerify);
        } else {
            s = new Socket();
            s.setSoTimeout(readTimeoutMs);
            s.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            log.debug("Thales socket open {}:{}", host, port);
        }
        s.setTcpNoDelay(true);
        return s;
    }

    /** Trust-all SSL factory — DEV ONLY. Production must set tls-insecure-skip-verify=false. */
    private static SSLSocketFactory insecureFactory() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{ new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
            @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new java.security.SecureRandom());
        return ctx.getSocketFactory();
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
