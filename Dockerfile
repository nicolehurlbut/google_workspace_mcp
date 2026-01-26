FROM python:3.11-slim

WORKDIR /server

# 1. System tools
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 2. Copy App
COPY secure_app.py /server/secure_app.py

# 3. INSTALL DEPENDENCIES
# Added 'pypdf' to the list
RUN pip install --no-cache-dir \
    fastmcp \
    google-auth \
    google-api-python-client \
    uvicorn \
    starlette \
    pypdf \
    openpyxl  

# 4. Copy remaining files
COPY . .

# 5. Permissions
RUN useradd --create-home --shell /bin/bash app 
RUN chown -R app:app /server && mkdir -p /app && chown -R app:app /app
USER app

# 6. Config
ENV PORT=8080
ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1 
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"

EXPOSE 8080

CMD ["python", "/server/secure_app.py"]