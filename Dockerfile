
# Base image
FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Add Go bin to PATH and use the same nuclei template location at build and runtime
ENV PATH="/root/go/bin:${PATH}"
ENV NUCLEI_TEMPLATES_DIR="/root/nuclei-templates"

# Pre-download nuclei templates at build time
RUN /root/go/bin/nuclei -ut -ud "$NUCLEI_TEMPLATES_DIR"

# Set working dir
WORKDIR /app

# Copy project
COPY . .

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
ENV PORT=8000

# Run app + scheduler
CMD ["sh", "-c", "python scheduler/runner.py & python app.py"]
