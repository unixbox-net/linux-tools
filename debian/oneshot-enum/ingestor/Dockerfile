FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OUT_DIR=/out \
    PGHOST=postgres \
    PGUSER=postgres \
    PGPASSWORD=postgres \
    PGDATABASE=oneshot \
    MINIO_ENDPOINT=minio:9000 \
    MINIO_ROOT_USER=minioadmin \
    MINIO_ROOT_PASSWORD=minioadmin \
    MINIO_BUCKET=oneshot-artifacts

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
ENTRYPOINT ["python","-u","/app/app.py"]

