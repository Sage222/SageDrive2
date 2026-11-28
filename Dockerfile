FROM python:3.11-slim-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbclient \
    libsmbclient-dev \
    gcc \
    ca-certificates \
    curl \
    iproute2 \
    wireguard-tools \
    python3-libtorrent \
    && rm -rf /var/lib/apt/lists/* \
    && echo "/usr/lib/python3/dist-packages" > /usr/local/lib/python3.11/site-packages/zz_debian_dist_packages.pth
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && (pip install --no-cache-dir --upgrade --prefer-binary libtorrent \
        && python3 -c "import libtorrent; print('libtorrent ready (PyPI wheel):', getattr(libtorrent, '__version__', libtorrent.version))") \
    || python3 -c "import libtorrent; print('libtorrent ready (apt fallback):', getattr(libtorrent, '__version__', libtorrent.version))"
RUN python3 -c "import urllib.request,json,tarfile,io,os,platform; arch='arm64' if 'aarch64' in platform.machine().lower() or 'arm64' in platform.machine().lower() else 'amd64'; req=urllib.request.Request('https://api.github.com/repos/pufferffish/wireproxy/releases/latest',headers={'User-Agent':'SageDrive/1.0'}); d=json.loads(urllib.request.urlopen(req,timeout=20).read().decode()); url=next(a['browser_download_url'] for a in d['assets'] if a['name']==f'wireproxy_linux_{arch}.tar.gz'); raw=urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'SageDrive/1.0'}),timeout=30).read(); tf=tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz'); m=next(x for x in tf.getmembers() if os.path.basename(x.name)=='wireproxy'); open('/usr/local/bin/wireproxy','wb').write(tf.extractfile(m).read()); os.chmod('/usr/local/bin/wireproxy',0o755); print('wireproxy installed:', d.get('tag_name'))" || true
COPY backend/ ./
COPY frontend/public/ ./static/
EXPOSE 8080 6881 6881/udp
CMD ["python", "main.py"]
