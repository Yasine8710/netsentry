FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir .

RUN useradd --system --uid 10001 --home /data netsentry \
    && mkdir -p /data/uploads && chown -R netsentry /data
USER netsentry

ENV NETSENTRY_DATABASE_URL=sqlite:////data/netsentry.db \
    NETSENTRY_UPLOAD_DIR=/data/uploads

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
