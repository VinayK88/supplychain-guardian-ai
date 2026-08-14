FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --create-home --uid 10001 guardian
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY dashboard ./dashboard
COPY data ./data
COPY models ./models

RUN python -m pip install --no-cache-dir ".[app]"

USER guardian
EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", "--server.address=0.0.0.0", "--server.port=8501"]

