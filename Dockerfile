FROM python:3.11-slim

WORKDIR /app

# 1. Install system tools
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 2. COPY THE APP (Explicitly, so we know it's there)
COPY secure_app.py /app/secure_app.py

# 3. INSTALL DEPENDENCIES (Critical Fix: We hardcode these to ensure they exist)
# We install 'mcp' and 'google-api-python-client' which are the core requirements.
# If you know you used a specific library like 'fastmcp', we install that too.
RUN pip install --no-cache-dir \
    fastmcp \
    "mcp[cli]" \
    google-auth \
    google-api-python-client \
    uvicorn \
    starlette

# 4. Copy any other files (like requirements.txt if it exists)
COPY . .

# 5. Create user
RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app
USER app

# 6. Configuration
ENV PORT=8080
ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1 
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"

EXPOSE 8080

# 7. RUN COMMAND (Using the explicit path)
CMD ["python", "/app/secure_app.py"]