FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
COPY static /app/static
RUN mkdir -p /app/data && chown -R 10001:10001 /app
USER 10001
ENV PORT=8080 SAIE_DB=/app/data/saie.sqlite3 SAIE_HTTPS=1
EXPOSE 8080
CMD ["python", "app.py"]
