FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install --no-cache-dir uv

COPY . .

# 1. Install dependencies into the system python
RUN uv sync --frozen --no-dev --system

# Create non-root user
RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app
USER app

ENV PORT=8080
EXPOSE ${PORT}

# 2. Run DIRECTLY with python (bypassing uv's isolation)
# Since we installed to --system, standard python can see everything.
CMD ["python", "secure_app.py"]