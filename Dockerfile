# Base Image: Python 3.11 Slim (Debian-based)
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install System Dependencies
# openjdk-21-jre-headless: Required for JADX and Apktool
# wget, unzip, curl: For downloading tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jre-headless \
    wget \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*



# Install Apktool
ENV APKTOOL_VERSION=2.12.1
RUN wget -q "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" -O /usr/local/bin/apktool.jar \
    && echo '#!/bin/bash\njava -jar /usr/local/bin/apktool.jar "$@"' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Install JADX
ENV JADX_VERSION=1.5.3
RUN wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O jadx.zip \
    && unzip -q jadx.zip -d /opt/jadx \
    && rm jadx.zip \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# Copy Python Dependencies
COPY requirements.txt .

# Install Python Libraries
RUN pip install --no-cache-dir -r requirements.txt

# Copy Application Source Code
COPY . .

# Make entrypoint executable
RUN chmod +x /app/scripts/ci/entrypoint.sh

# Create Output Directory
RUN mkdir -p /app/output

# Set Entrypoint
ENTRYPOINT ["python", "-m", "apppredator.cli"]

# Default Command (Show Help)
CMD ["--help"]
