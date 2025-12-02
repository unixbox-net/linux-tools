FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir simplejson
COPY urlgen.py /app/urlgen.py
ENTRYPOINT ["python", "/app/urlgen.py"]

