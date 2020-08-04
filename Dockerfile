FROM python:3-alpine AS build
RUN apk add --no-cache gcc linux-headers musl-dev
RUN pip wheel netifaces

FROM python:3-alpine

COPY --from=build /netifaces*.whl /tmp
RUN pip install /tmp/netifaces*.whl
COPY multicast-relay.py /
COPY start.sh /

ENTRYPOINT [ "sh", "start.sh", "--foreground" ]
