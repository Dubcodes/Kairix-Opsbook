FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iputils-ping tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY kairix ./kairix
COPY templates ./templates
COPY static ./static

EXPOSE 8000

CMD ["uvicorn", "kairix.main:app", "--host", "0.0.0.0", "--port", "8000"]
