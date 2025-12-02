FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY report.py /app/report.py
COPY templates /app/templates
ENTRYPOINT ["python","/app/report.py"]
