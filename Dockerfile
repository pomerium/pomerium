FROM node:lts-bookworm@sha256:42a4d97d4abf2f278c323370cf9c8dbccc2a238acceebceb53711926ecfb4110 as ui
WORKDIR /build

COPY .git ./.git
COPY Makefile ./Makefile

# download yarn dependencies
COPY ui/yarn.lock ./ui/yarn.lock
COPY ui/package.json ./ui/package.json
RUN make yarn

# build ui
COPY ./ui/ ./ui/
RUN make build-ui

FROM golang:1.21.4-bookworm@sha256:52362e252f452df17c24131b021bf2ebf1c9869f65c28f88ddb326191defea9c as build
WORKDIR /go/src/github.com/pomerium/pomerium

RUN apt-get update \
    && apt-get -y --no-install-recommends install zip

# cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /build/ui/dist ./ui/dist

# build
RUN make build-go NAME=pomerium
RUN touch /config.yaml

FROM gcr.io/distroless/base-debian12:debug@sha256:d2890b2740037c95fca7fe44c27e09e91f2e557c62cf0910d2569b0dedc98ddc
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
