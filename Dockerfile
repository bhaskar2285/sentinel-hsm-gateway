# syntax=docker/dockerfile:1.7
FROM eclipse-temurin:25-jdk AS build
WORKDIR /src
COPY pom.xml ./
COPY modules ./modules
RUN --mount=type=cache,target=/root/.m2 \
    apt-get update && apt-get install -y --no-install-recommends maven && rm -rf /var/lib/apt/lists/* && \
    mvn -B -T 1C -DskipTests package

FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app
RUN useradd -r -u 1500 sentinel
COPY --from=build /src/modules/gateway-api/target/sentinel-hsm-gateway.jar /app/app.jar
# Writable, image-owned dir for the persisted JWE key (survives restarts via a
# named volume mounted here). /app/certs is mounted read-only for the TLS keystore.
RUN mkdir -p /app/jwe && chown 1500:1500 /app/jwe
USER sentinel
EXPOSE 8080
ENV JAVA_OPTS="-XX:+UseZGC -XX:MaxRAMPercentage=75.0"
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar /app/app.jar"]
