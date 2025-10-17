FROM python:3.10-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

EXPOSE 8501
CMD ["streamlit", "run", "src/trusted_ai_soc_lite/dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
