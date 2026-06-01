# Safe Dockerfile -- clean of all docker-001..docker-005 detectors
# Used by TestDockerAdapter / TestDockerAdapterDepth

# Safe: pinned to a specific digest-stable tag (not :latest)
FROM python:3.12-slim

# Safe: DB_PASSWORD sourced from build-arg, never hardcoded as a literal
ARG DB_PASSWORD
ENV DB_PASSWORD=${DB_PASSWORD}

# Safe: only expose the application port, not sensitive service ports
EXPOSE 8080

# Safe: COPY instead of ADD for local files
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

WORKDIR /app
COPY . .

# Safe: explicit non-root USER directive (satisfies docker-002)
RUN useradd -m appuser
USER appuser

CMD ["python", "app.py"]
