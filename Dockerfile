FROM python:3.12-slim
WORKDIR /app
COPY src /app/src
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-m", "reverse_shell_decoy"]
CMD ["simulate", "--presentation", "realistic"]
