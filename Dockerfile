FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml .
COPY src ./src
RUN pip install --no-cache-dir .
# Najpierw wytrenuj model lokalnie: python -m phish_detector.train ...
COPY models ./models
ENV MODEL_PATH=/app/models/model.joblib
EXPOSE 8000
CMD ["uvicorn", "phish_detector.api:app", "--host", "0.0.0.0", "--port", "8000"]
