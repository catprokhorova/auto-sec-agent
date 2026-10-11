# Ephemeral sandbox execution container for playground microservice
FROM python:3.11-slim

WORKDIR /app

# Install minimal test dependencies
RUN pip install --no-cache-dir pytest

# Copy service and test suite
COPY auth_service/ /app/playground/auth_service/

# Default command: run pytest
CMD ["pytest", "playground/auth_service/test_service.py", "-v"]
