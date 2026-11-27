FROM python:3.11-slim

# Install existing dependencies + Samba, Rclone, FUSE, FFmpeg, and native libtorrent
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbclient \
    libsmbclient-dev \
    gcc \
    samba \
    rclone \
    fuse3 \
    ffmpeg \
    python3-libtorrent \
    && rm -rf /var/lib/apt/lists/* \
    && echo "/usr/lib/python3/dist-packages" > /usr/local/lib/python3.11/site-packages/debian_dist_packages.pth

# Fix FUSE permissions
RUN sed -i 's/#user_allow_other/user_allow_other/' /etc/fuse.conf

WORKDIR /app
ENV DATA_DIR=/app/data
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files to /app
COPY backend/ ./
# CRITICAL FIX: Copy frontend files to /app/static where Flask expects them!
COPY frontend/public/ ./static/

# Move Samba config
COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080 445 6881 6881/udp
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
