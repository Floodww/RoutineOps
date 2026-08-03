FROM debian:12-slim

# Xvfb — X-сервер без монитора; x11-utils даёт xwininfo/xdpyinfo (чем проверяем
# геометрию и override-redirect), xdotool — синтетический ввод, imagemagick —
# скриншот в png, xfonts-* — растровые шрифты iso10646-1, которыми рисует замок.
RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb x11-utils xdotool imagemagick xfonts-base xfonts-100dpi xfonts-75dpi \
        procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /harness
COPY agent /harness/agent
COPY run-in-container.sh /harness/run-in-container.sh
RUN chmod +x /harness/agent /harness/run-in-container.sh

ENTRYPOINT ["/harness/run-in-container.sh"]
