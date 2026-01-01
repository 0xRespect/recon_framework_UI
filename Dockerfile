# Use Python 3.9 slim image as base
FROM python:3.9-slim

# Install system dependencies and Go
# Go is needed to install the recon tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    unzip \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for Go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# Install Recon Tools
# 1. Subfinder (ProjectDiscovery)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 2. Assetfinder (TomNomNom)
RUN go install github.com/tomnomnom/assetfinder@latest

# 3. Findomain
# Findomain binary installation is often more reliable than cargo/source for quick setup on linux
RUN curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
    && unzip findomain-linux.zip \
    && chmod +x findomain \
    && mv findomain /usr/local/bin/ \
    && rm findomain-linux.zip

# 4. HTTPX (ProjectDiscovery)
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 5. Katana (ProjectDiscovery)
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

# 6. GAU (GetAllUrls)
RUN go install github.com/lc/gau/v2/cmd/gau@latest

# 7. Nuclei (ProjectDiscovery)
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 8. FFUF
RUN go install github.com/ffuf/ffuf/v2@latest

# Install Wordlists (SecLists)
# Using a specific commit depth or just a subset might be faster, but user requested 'big.txt' which is large.
# We'll clone the repository to a standard location.
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set the entrypoint to run the main script
# Using "python" "main.py" allows arguments to be passed easily, 
# but since the script requires interactive input or args, we'll stick to bash or allow overriding.
# For now, let's default to bash so the user can interact, or they can override the command.
ENTRYPOINT ["python", "main.py"]
