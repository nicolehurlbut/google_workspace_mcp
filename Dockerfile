FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install --no-cache-dir uv

COPY . .

# Install dependencies (ensure 'fastmcp' is included)
RUN uv sync --frozen --no-dev

# Create non-root user
RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app
USER app

ENV PORT=8080
EXPOSE ${PORT}

# Run the Secure MCP App
# We use 'uv run' to ensure we use the environment with dependencies
# The --port and --host flags depend on how fastmcp implements run()
# Usually fastmcp uses uvicorn under the hood. 
CMD ["uv", "run", "secure_app.py"]