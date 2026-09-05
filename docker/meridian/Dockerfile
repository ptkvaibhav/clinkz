# Meridian Portal — the third authentication shape.
#
# Standard library only, so there is no wheel build, no lockfile entry, and no
# reason for this image to drift from the app.py the pytest fixture imports.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py

ENV MERIDIAN_PORT=8090 \
    MERIDIAN_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

EXPOSE 8090

# A container that starts is not a target that answers. The healthcheck asks the
# public route, which is the one route whose answer does not depend on a session.
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/pricing', timeout=2).status==200 else 1)"

CMD ["python", "/app/app.py"]
