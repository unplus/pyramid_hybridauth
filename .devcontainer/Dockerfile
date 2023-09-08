FROM ghcr.io/unplus/poetry:1.4.2-py3.11.3

RUN poetry config virtualenvs.create true \
    && poetry config virtualenvs.in-project true

WORKDIR /opt/dev

COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --no-interaction --no-ansi
