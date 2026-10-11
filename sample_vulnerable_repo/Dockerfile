# Insecure sample Dockerfile demonstrating OWASP container misconfigurations
FROM python:latest

WORKDIR /app

# SEC-A02-006: Hardcoded secret in ENV
ENV DATABASE_PASSWORD="super_secret_docker_password_9999"

COPY requirements.txt .
RUN pip install -r requirements.txt

# CIS-DOCKER-004: Insecure curl to bash execution
RUN curl -sSL https://install.example.com/agent.sh | bash

COPY . .

# SEC-A05-005: Running as root
USER root

EXPOSE 5000

CMD ["python", "app.py"]
