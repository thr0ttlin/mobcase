# mobcase: cross-platform mobile app testing toolkit
#
# Build:  docker build -t mobcase .
#         docker build --build-arg FRIDA_VERSION=17.2.7 -t mobcase .   # pin frida
#
# Run (iOS, bridge host usbmuxd: no privileged needed):
#   docker run --rm -it -v /run/usbmuxd:/run/usbmuxd \
#     -v /var/lib/lockdown:/var/lib/lockdown:ro mobcase mbcdev list
#
# Run (Android + iOS over USB passthrough):
#   docker run --rm -it --privileged -v /dev/bus/usb:/dev/bus/usb mobcase mbcdev list
#
# Run (reach the host's adb server instead of USB passthrough):
#   docker run --rm -it --network host mobcase mbcdev list
#
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PATH=/root/.local/bin:$PATH

WORKDIR /opt/mobcase
COPY . /opt/mobcase

# --- external tools (same script the host bootstrap uses) ------------------- #
# Reuses scripts/install-deps.sh so the toolchain is defined in one place. The
# apktool/ldid downloads are best-effort with bounded timeouts (a blocked GitHub
# no longer fails the build). If your build network can't reach GitHub, point at
# mirrors:  --build-arg APKTOOL_JAR_URL=<url> --build-arg LDID_URL=<url>
# ...or build with host networking:  docker build --network=host -t mobcase .
ARG APKTOOL_WRAPPER_URL=
ARG APKTOOL_JAR_URL=
ARG LDID_URL=
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip pipx git \
    && APKTOOL_WRAPPER_URL="$APKTOOL_WRAPPER_URL" APKTOOL_JAR_URL="$APKTOOL_JAR_URL" \
       LDID_URL="$LDID_URL" bash scripts/install-deps.sh \
    && rm -rf /var/lib/apt/lists/*

# --- mobcase via pipx (isolated venv, mbc* on PATH) ------------------------ #
RUN pipx install /opt/mobcase && chmod +x scripts/entrypoint.sh

# frida for iOS app launch / instrumentation - installed by default (latest).
# Pin to your device's frida-server major:  --build-arg FRIDA_VERSION=17.19.0
# Skip it entirely: --build-arg SKIP_FRIDA=1.
ARG FRIDA_VERSION=
ARG SKIP_FRIDA=
RUN if [ "$SKIP_FRIDA" = "1" ]; then \
        echo "use SKIP_FRIDA=1: not installing frida"; \
    elif [ -n "$FRIDA_VERSION" ]; then \
        pipx inject mobcase "frida==${FRIDA_VERSION}" || echo "frida inject failed (optional)"; \
    else \
        pipx inject mobcase frida || echo "frida inject failed (optional)"; \
    fi

ENTRYPOINT ["/opt/mobcase/scripts/entrypoint.sh"]
CMD ["bash"]