FROM python:3.11-slim

# 1. Use a DIFFERENT folder for the code (Avoids the secret mount conflict)
WORKDIR /server

# 2. Install system tools
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 3. Copy the app to the NEW location
COPY secure_app.py /server/secure_app.py

# 4. INSTALL DEPENDENCIES (The Fix)
# We added 'fastmcp-server' back to the list.
RUN pip install --no-cache-dir \
    fastmcp-server \
    google-auth \
    google-api-python-client \
    uvicorn \
    starlette

# 5. Copy everything else (in case you have local modules)
COPY . .

# 6. Create user & Fix Permissions
RUN useradd --create-home --shell /bin/bash app 
# Give user ownership of BOTH folders
RUN chown -R app:app /server && mkdir -p /app && chown -R app:app /app
USER app

# 7. Config
ENV PORT=8080
ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1 
# The secret still lives in the old spot (safe and isolated now)
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"

EXPOSE 8080

# 8. Run from the NEW location
CMD ["python", "/server/secure_app.py"]