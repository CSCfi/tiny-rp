FROM python:3.12.1-alpine3.19 as BUILD

RUN apk add --update \
    && apk add --no-cache --virtual build-base libressl-dev libffi-dev gcc musl-dev python3-dev \
    && rm -rf /var/cache/apk/*

COPY requirements.txt /root/requirements.txt

RUN pip install --upgrade pip && \
    pip install -r /root/requirements.txt

FROM python:3.12.1-alpine3.19

RUN apk add --no-cache --update bash

COPY --from=BUILD /usr/local/lib/python3.12/ /usr/local/lib/python3.12/

COPY --from=BUILD /usr/local/bin/uvicorn /usr/local/bin/

RUN mkdir -p /app

WORKDIR /app

COPY ./deploy/app.sh /app/app.sh

COPY ./main.py /app/main.py

RUN chmod +x /app/app.sh

RUN addgroup -g 1001 app && \
    adduser -D -u 1001 --disabled-password \
    --no-create-home -G app app

ENTRYPOINT ["/bin/sh", "-c", "/app/app.sh"]
