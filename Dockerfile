FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY threatpulse ./threatpulse
COPY config.example.toml ./config.toml
RUN useradd -r -u 10001 tp && mkdir -p /app/data && chown -R tp /app
USER tp
EXPOSE 8080
CMD ["python", "-m", "threatpulse", "serve", "--port", "8080"]
