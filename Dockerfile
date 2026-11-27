FROM python:3.11-slim-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbclient \
    libsmbclient-dev \
    gcc \
    python3-libtorrent \
    && rm -rf /var/lib/apt/lists/* \
    && echo "/usr/lib/python3/dist-packages" > /usr/local/lib/python3.11/site-packages/debian_dist_packages.pth
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && (python3 -c "import libtorrent; print('libtorrent ready (apt):', getattr(libtorrent, '__version__', libtorrent.version))" \
        || (pip install --no-cache-dir --prefer-binary libtorrent && python3 -c "import libtorrent; print('libtorrent ready (pip):', getattr(libtorrent, '__version__', libtorrent.version))"))
COPY backend/ ./
COPY frontend/public/ ./static/
EXPOSE 8080 6881 6881/udp
CMD ["python", "main.py"]
