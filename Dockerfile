FROM python:3.11-slim

# 1. Separate code from secret mount
WORKDIR /server

# 2. System tools
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 3. Copy App
COPY secure_app.py /server/secure_app.py

# 4. INSTALL DEPENDENCIES (THE FIX)
# We changed 'fastmcp-server' to 'fastmcp'
RUN pip install --no-cache-dir \
    fastmcp \
    google-auth \
    google-api-python-client \
    uvicorn \
    starlette

# 5. Copy remaining files
COPY . .

# 6. Permissions
RUN useradd --create-home --shell /bin/bash app 
RUN chown -R app:app /server && mkdir -p /app && chown -R app:app /app
USER app

# 7. Config
ENV PORT=8080
ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1 
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"

EXPOSE 8080

CMD ["python", "/server/secure_app.py"]