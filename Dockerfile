FROM python:3.11-slim

WORKDIR /app

# 1. Install system tools
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 2. Copy ALL files
COPY . .

# --- DEBUG STEP: Print all files to the build log ---
RUN echo "⬇️ ⬇️ ⬇️ CONTENTS OF /APP ⬇️ ⬇️ ⬇️" && ls -la /app && echo "⬆️ ⬆️ ⬆️ END CONTENTS ⬆️ ⬆️ ⬆️"

# 3. Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 4. Create user
RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app
USER app

# 5. Config
ENV PORT=8080
ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1 
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"

EXPOSE 8080

CMD ["python", "secure_app.py"]