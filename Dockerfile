FROM eclipse-temurin:17 as jre-build
RUN $JAVA_HOME/bin/jlink \
        --verbose \
        --add-modules java.base,java.desktop,java.logging,java.management,java.naming,java.security.jgss,java.instrument,java.sql,jdk.unsupported,java.net.http,jdk.crypto.ec \
        --strip-debug \
        --no-man-pages \
        --no-header-files \
        --compress=2 \
        --output /opt/javaruntime

FROM debian:buster-slim as base

# Default to UTF-8 file.encoding
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

ENV JAVA_HOME=/opt/java/openjdk
ENV PATH $JAVA_HOME/bin:$PATH

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iputils-ping \
        curl \
        wget \
        fontconfig \
        tcpdump \
        # locales ensures proper character encoding and locale-specific behaviors using en_US.UTF-8
        locales \
    ; \
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen; \
    locale-gen en_US.UTF-8; \
    rm -rf /var/lib/apt/lists/*

COPY --from=jre-build /opt/javaruntime $JAVA_HOME

RUN mkdir /opt/app
COPY ./target/auth-server-*.jar /opt/app/app.jar

ENTRYPOINT [ "java", "-jar", "/opt/app/app.jar" ]