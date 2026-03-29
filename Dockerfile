
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

# Add Go bin to PATH
ENV PATH="/root/go/bin:${PATH}"

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