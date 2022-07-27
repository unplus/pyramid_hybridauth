FROM ghcr.io/unplus/poetry:1.1.13-py3.7.13

RUN poetry config virtualenvs.create true \
    && poetry config virtualenvs.in-project true

WORKDIR /opt/dev

# COPY pyproject.toml poetry.lock ./
# RUN poetry install --no-root --no-interaction --no-ansi
