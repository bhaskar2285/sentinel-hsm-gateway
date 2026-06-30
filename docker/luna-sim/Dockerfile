# ProtectToolkit-C software-emulation HSM (PKCS#11 backend for the Luna adapter).
# Build for amd64 (the PTK debs are x86_64): docker build --platform linux/amd64 -t ptk-sim:7.2.3 .
# Host one-time: docker run --privileged --rm tonistiigi/binfmt --install amd64
FROM --platform=linux/amd64 debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        procps libcap2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The SW emulator (libctsw.so), the cryptoki symlink (libcryptoki.so -> libctsw.so) and the
# ctconf/ctstat/ctkmu tools all ship in PTKcpsdk. PTKcprt is NOT installed: it declares a
# dependency on a hardware access provider (ptkhsmpvdr) which would leave dpkg in a broken
# state and block later apt installs (e.g. the JRE). cpsdk alone is self-sufficient for SW mode.
COPY PTKcpsdk-7.2.3-0-x86_64.deb /tmp/
RUN dpkg -i /tmp/PTKcpsdk-7.2.3-0-x86_64.deb; rm -f /tmp/*.deb

ENV CPROVDIR=/opt/safenet/protecttoolkit7/ptk \
    PATH=/opt/safenet/protecttoolkit7/ptk/bin:/usr/bin:/bin \
    LD_LIBRARY_PATH=/opt/safenet/protecttoolkit7/ptk/lib

COPY init-token.sh /usr/local/bin/init-token.sh
RUN chmod +x /usr/local/bin/init-token.sh

CMD ["bash"]
