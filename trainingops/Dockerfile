FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dipendenze di sistema minime (puoi estendere se usi librerie native)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Requirements
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copia progetto
COPY . /app

# Directory runtime (sqlite + uploads)
RUN mkdir -p /app/uploads /app/uploads/cv /app/data

EXPOSE 8000

# Avvio con Gunicorn (Linux container)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "wsgi:app", "--access-logfile", "-", "--error-logfile", "-"]
