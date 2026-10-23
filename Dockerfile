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

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4)"

CMD ["python", "-m", "siem", "serve", "--host", "0.0.0.0", "--port", "8080", \
     "--database", "data/siem.db", "--alerts", "data/all-alerts.jsonl"]

