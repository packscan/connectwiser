FROM python:3.13-slim
WORKDIR /app
COPY . .
ENV PORT=8787 BIND=0.0.0.0
EXPOSE 8787
CMD ["python", "server.py"]
