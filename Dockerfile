# PVS - Personal Vulnerability Scanner & Remediation Engine
# Production Container Image

FROM python:3.11-slim as runtime

LABEL maintainer="Mohamed Essam Elsadany <pvs@security.dev>"
LABEL description="PVS - Personal Vulnerability Scanner & Remediation Engine"

WORKDIR /app

# Install minimal system dependencies
RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml setup.py requirements.txt LICENSE README.md /app/
COPY pvs /app/pvs

# Install package
RUN pip install --no-cache-dir .

# Create reports volume directory
RUN mkdir -p /app/reports && chmod 777 /app/reports

VOLUME ["/app/reports"]

ENTRYPOINT ["pvs"]
CMD ["quick"]
