FROM python:3.12-slim

ARG APP_VERSION=0.1.17
ARG APP_BUILD=
ARG APP_BUILD_ITERATION=
ARG APP_REVISION=

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_VERSION=$APP_VERSION \
    APP_BUILD=$APP_BUILD \
    APP_BUILD_ITERATION=$APP_BUILD_ITERATION \
    APP_REVISION=$APP_REVISION

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
