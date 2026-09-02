# Уже существующий локальный образ с Python 3.13 и argon2-cffi.
FROM infosec-lab13:local
USER root
WORKDIR /fastapi-lab
COPY requirements.txt .
RUN python3 -m ensurepip && python3 -m pip install --no-cache-dir -r requirements.txt
COPY audit.py ./
COPY vulnerable ./vulnerable
COPY hardened ./hardened
RUN mkdir -p /data && chown 65534:65534 /data
USER 65534:65534
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3"]
CMD ["audit.py"]
