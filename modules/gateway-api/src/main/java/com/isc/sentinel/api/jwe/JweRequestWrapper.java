package com.isc.sentinel.api.jwe;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class JweRequestWrapper extends HttpServletRequestWrapper {

    private final byte[] body;
    /** Headers carried INSIDE the encrypted JWE envelope, overlaid on the real request. */
    private final Map<String, String> headerOverlay;

    public JweRequestWrapper(HttpServletRequest request, byte[] body) {
        this(request, body, Collections.emptyMap());
    }

    public JweRequestWrapper(HttpServletRequest request, byte[] body, Map<String, String> headerOverlay) {
        super(request);
        this.body = body;
        // Case-insensitive per the HTTP header contract.
        this.headerOverlay = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headerOverlay != null) this.headerOverlay.putAll(headerOverlay);
    }

    @Override
    public String getHeader(String name) {
        String overlaid = headerOverlay.get(name);
        return overlaid != null ? overlaid : super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        String overlaid = headerOverlay.get(name);
        return overlaid != null
            ? Collections.enumeration(java.util.List.of(overlaid))
            : super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        Set<String> names = new LinkedHashSet<>();
        Enumeration<String> original = super.getHeaderNames();
        while (original != null && original.hasMoreElements()) names.add(original.nextElement());
        names.addAll(headerOverlay.keySet());
        return Collections.enumeration(names);
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream stream = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            public int read() throws IOException { return stream.read(); }
            public boolean isFinished() { return stream.available() == 0; }
            public boolean isReady() { return true; }
            public void setReadListener(ReadListener listener) {}
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }

    @Override
    public String getContentType() {
        return "application/json";
    }

    @Override
    public int getContentLength() {
        return body.length;
    }

    @Override
    public long getContentLengthLong() {
        return body.length;
    }
}
