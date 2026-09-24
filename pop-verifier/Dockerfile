FROM python:3.13-alpine

RUN addgroup -S verifier && adduser -S -G verifier verifier
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=verifier:verifier app.py .

USER verifier
EXPOSE 9443
CMD ["python", "/app/app.py"]
