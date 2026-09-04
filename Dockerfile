FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY secure ./secure
USER nobody
EXPOSE 8000
CMD ["uvicorn", "secure.app:app", "--host", "0.0.0.0", "--port", "8000"]
