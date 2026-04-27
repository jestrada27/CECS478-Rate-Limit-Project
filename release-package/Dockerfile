FROM python:3.11-slim

# ── Least-privilege: create a non-root user ─────────────────────────────────
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Install dependencies as root, then hand off
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create log dir and set permissions
RUN mkdir -p /app/artifacts/release \
    && chown -R appuser:appgroup /app

# Drop to non-root for runtime
USER appuser

EXPOSE 5000

CMD ["python", "app/main.py"]
