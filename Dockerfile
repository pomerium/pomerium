FROM gcr.io/distroless/static
RUN touch /pomerium/config.yaml
COPY pomerium /bin/pomerium
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]