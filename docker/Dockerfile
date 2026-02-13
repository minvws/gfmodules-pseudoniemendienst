# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.14

FROM python:${PYTHON_VERSION}-slim AS base

ARG PROJECT_DIR="/src"
ARG APP_USER="app"
ARG APP_GROUP="app"
ARG NEW_UID=1000
ARG NEW_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.2

# Create a non-privileged user that the app will run under.
RUN groupadd --system ${APP_GROUP} --gid=${NEW_GID} && \
    adduser \
        --disabled-password \
        --gecos "" \
        --uid ${NEW_UID} \
        --gid ${NEW_GID} \
        ${APP_USER}

# Builder stage for compilation and dependencies
FROM base AS builder

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        pkg-config \
        libssl-dev \
        libsodium-dev \
        build-essential \
        swig \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install poetry==${POETRY_VERSION}

# Compile liboprf
WORKDIR /liboprf
RUN git clone --depth 1 --branch v0.9.3 https://github.com/stef/liboprf.git . && \
    cd src && \
    make

# Install Python dependencies
WORKDIR ${PROJECT_DIR}
COPY ./pyproject.toml ./poetry.lock ./

ENV POETRY_CACHE_DIR=/root/.cache/poetry \
    POETRY_VIRTUALENVS_CREATE=false

RUN --mount=type=cache,target=/root/.cache/poetry \
    poetry install --no-root --no-interaction --only main

# Final stage
FROM base AS final

ARG PYTHON_VERSION

# Install only runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        openssl \
        curl \
        libssl3 \
        libsodium23 \
        postgresql-client \
        gettext-base \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ${PROJECT_DIR}

# Copy compiled libraries
COPY --from=builder --chown=${APP_USER}:${APP_GROUP} /liboprf/src/noise_xk/lib*.so /usr/local/lib/
COPY --from=builder --chown=${APP_USER}:${APP_GROUP} /liboprf/src/lib*.so /usr/local/lib/
RUN ldconfig

# Copy Python packages
COPY --chown=${APP_USER}:${APP_GROUP} --from=builder /usr/local/lib/python${PYTHON_VERSION}/site-packages /usr/local/lib/python${PYTHON_VERSION}/site-packages

# Copy application
COPY --chown=${APP_USER}:${APP_GROUP} . ${PROJECT_DIR}

# Copy and set permissions on entrypoint scripts
COPY --chmod=755 ./docker/init-standalone.sh /usr/local/bin/
COPY --chmod=755 ./docker/init.sh /usr/local/bin/

ARG standalone=false

RUN if [ "$standalone" = "true" ] ; then \
    ln -sf /usr/local/bin/init-standalone.sh /docker-entrypoint.sh; \
  else \
    ln -sf /usr/local/bin/init.sh /docker-entrypoint.sh ; \
  fi

USER ${APP_USER}

ENV PYTHONPATH=${PROJECT_DIR}

ENTRYPOINT ["/docker-entrypoint.sh"]
