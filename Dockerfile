FROM python:3.11-slim-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbclient \
    libsmbclient-dev \
    gcc \
    python3-libtorrent \
    && rm -rf /var/lib/apt/lists/* \
    && echo "/usr/lib/python3/dist-packages" > /usr/local/lib/python3.11/site-packages/zz_debian_dist_packages.pth
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && (pip install --no-cache-dir --upgrade --prefer-binary libtorrent \
        && python3 -c "import libtorrent; print('libtorrent ready (PyPI wheel):', getattr(libtorrent, '__version__', libtorrent.version))") \
    || python3 -c "import libtorrent; print('libtorrent ready (apt fallback):', getattr(libtorrent, '__version__', libtorrent.version))"
COPY backend/ ./
COPY frontend/public/ ./static/
EXPOSE 8080 6881 6881/udp
CMD ["python", "main.py"]
