ARG BASE_IMAGE=ghcr.io/meta-pytorch/openenv-base:latest
FROM ${BASE_IMAGE}

WORKDIR /app/env
COPY . /app/env

RUN uv pip install --system -e .

ENV PYTHONPATH="/app/env:${PYTHONPATH}"
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]

