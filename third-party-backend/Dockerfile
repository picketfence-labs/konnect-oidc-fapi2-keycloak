FROM python:3.13-alpine

RUN addgroup -S -g 1000 backend && adduser -S -u 1000 -G backend backend
WORKDIR /app
COPY --chown=backend:backend app.py .
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER backend
EXPOSE 9444
CMD ["python", "-B", "/app/app.py"]
