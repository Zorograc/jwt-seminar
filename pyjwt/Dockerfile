FROM python:3.11-slim
WORKDIR /app
RUN pip install flask PyJWT==2.8.0 cryptography
COPY app.py .
CMD ["python", "app.py"]