# ---------------------------------------------------------
# Stage 1: install dependencies
# ---------------------------------------------------------

FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    --prefix=/install \
    -r requirements.txt


# ---------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------

FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy only installed dependencies from builder.
COPY --from=builder /install /usr/local

# Copy application.
COPY app.py .

# Create an unprivileged user.
RUN useradd \
    --create-home \
    --shell /usr/sbin/nologin \
    appuser

# Run the application as the non-root user.
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
