package com.isc.sentinel.api.jwe;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

public class JweResponseWrapper extends HttpServletResponseWrapper {

    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public JweResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    @Override
    public ServletOutputStream getOutputStream() {
        return new ServletOutputStream() {
            public void write(int b) { buffer.write(b); }
            public boolean isReady() { return true; }
            public void setWriteListener(WriteListener listener) {}
        };
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        return new PrintWriter(buffer, true);
    }

    @Override
    public void flushBuffer() {
        // no-op: prevent premature flush to underlying response
    }

    public byte[] capturedBody() {
        return buffer.toByteArray();
    }
}
