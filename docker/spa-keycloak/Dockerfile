# Northwind Notes — the SPA + separate-origin Keycloak authentication shape.
#
# Standard library only, like docker/meridian: no wheel build, no lockfile entry.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py

ENV NW_PORT=8000 \
    NW_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/assets/app.css', timeout=2).status==200 else 1)"

CMD ["python", "/app/app.py"]
