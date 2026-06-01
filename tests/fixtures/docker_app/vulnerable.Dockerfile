# Vulnerable Dockerfile -- triggers docker-001 through docker-005
# Used by TestDockerAdapter / TestDockerAdapterDepth

# docker-005: mutable :latest tag (non-reproducible build)
FROM python:latest

# docker-001: hardcoded secret in ENV literal
ENV DB_PASSWORD=supersecretvalue
ENV API_SECRET=abc123verysecret

# docker-003: exposing sensitive SSH and database ports
EXPOSE 22
EXPOSE 3306

# docker-004: ADD instead of COPY (can fetch remote URLs, auto-extract archives)
ADD requirements.txt /app/requirements.txt

RUN pip install -r /app/requirements.txt

WORKDIR /app
COPY . .

# docker-002: no USER directive -- container runs as root
CMD ["python", "app.py"]
