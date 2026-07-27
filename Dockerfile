FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    semgrep \
    bandit \
    safety

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

RUN GITLEAKS_VERSION=$(curl -sL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
    | grep '"tag_name":' | cut -d'"' -f4) && \
    curl -sL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

RUN HADOLINT_VERSION=$(curl -sL https://api.github.com/repos/hadolint/hadolint/releases/latest \
    | grep '"tag_name":' | cut -d'"' -f4) && \
    curl -sL "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
    -o /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

COPY run_audit.sh /usr/local/bin/run_audit.sh
COPY aggregate_report.py /opt/aggregate_report.py
RUN chmod +x /usr/local/bin/run_audit.sh

WORKDIR /workspace
ENTRYPOINT ["run_audit.sh"]
