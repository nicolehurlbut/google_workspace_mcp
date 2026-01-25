FROM python:3.11-slim

WORKDIR /app

# 1. Install system tools
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 2. Copy ALL project files first
# (Required because requirements.txt refers to the current folder with '-e .')
COPY . .

# 3. Install dependencies using standard PIP
# This reads the requirements.txt you generated with 'uv export'
RUN pip install --no-cache-dir -r requirements.txt

# 4. Create user & Permissions (Security Best Practice)
RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app
USER app

# 5. Configuration
ENV PORT=8080
ENV HOST=0.0.0.0
# IMPORTANT: Force logs to show up immediately
ENV PYTHONUNBUFFERED=1 

EXPOSE 8080

# 6. Run the Secure App directly
CMD ["python", "secure_app.py"]