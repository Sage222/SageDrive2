FROM python:3.12-slim

# Install existing dependencies + Samba, Rclone, FUSE, and FFmpeg
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbclient \
    libsmbclient-dev \
    gcc \
    samba \
    rclone \
    fuse3 \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Fix FUSE permissions
RUN sed -i 's/#user_allow_other/user_allow_other/' /etc/fuse.conf

WORKDIR /app
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

EXPOSE 8080 445
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
