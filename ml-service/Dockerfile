FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY requirements-runtime.txt /app/
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements-runtime.txt

# Copy only inference-serving code. Training, capture processing, notebooks,
# tests, and all datasets stay outside the image.
COPY --chown=app:app config/model.yaml /app/config/model.yaml
COPY --chown=app:app src/grpc_server.py src/predict.py src/schemas.py src/explain.py src/unknown_detection.py /app/src/
COPY --chown=app:app proto /app/proto

# A build must contain the selected persisted model, its metadata, and model
# selection metadata. Docker fails early when any required artifact is absent.
COPY --chown=app:app models/ /app/models/
COPY --chown=app:app artifacts/training_metrics.json /app/artifacts/training_metrics.json

COPY --chown=app:app docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod 0555 /app/docker-entrypoint.sh

USER app

EXPOSE 50051

ENTRYPOINT ["/app/docker-entrypoint.sh"]
