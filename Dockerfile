FROM python:3.11-slim

WORKDIR /app

# 1. Install system tools
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 2. Install uv
RUN pip install --no-cache-dir uv

# 3. Copy files
COPY . .

# 4. CONFIGURE UV TO USE SYSTEM PYTHON
# instead of the --system flag, we tell uv where the environment is.
# /usr/local is the default install location for python:slim images.
ENV UV_PROJECT_ENVIRONMENT="/usr/local"

# 5. Sync dependencies
# This will now verify the lockfile and install everything into /usr/local
RUN uv sync --frozen --no-dev

# 6. Create user & Permissions
RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app
USER app

ENV PORT=8080
EXPOSE 8080

# 7. Run
CMD ["python", "secure_app.py"]