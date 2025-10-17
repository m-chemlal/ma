FROM python:3.10-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

CMD ["sh", "-c", "while true; do python -m trusted_ai_soc_lite; sleep 300; done"]
