FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir .
RUN useradd --create-home --uid 10001 siem
RUN mkdir -p /app/data /app/reports /app/quarantine \
    && chown -R siem:siem /app

USER siem
ENV PYTHONUNBUFFERED=1
ENV SIEM_API_KEY=

EXPOSE 8080
VOLUME ["/app/data", "/app/reports", "/app/quarantine"]

CMD ["python", "-m", "siem", "serve", "--host", "0.0.0.0", "--port", "8080"]

