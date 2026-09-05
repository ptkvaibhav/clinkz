# Protopoll — a target whose Object.prototype can actually be polluted.
#
# Node's own standard library only, so there is no package.json, no wheel or npm
# build, no lockfile entry, and no reason for this image to drift from the
# app.js the pytest fixture runs directly. Same reasoning as docker/meridian.
FROM node:22-alpine

WORKDIR /app
COPY app.js /app/app.js

ENV PROTOPOLL_PORT=8095 \
    PROTOPOLL_HOST=0.0.0.0 \
    NODE_ENV=production

# PROTOPOLL_RESET_TOKEN is deliberately NOT set here. Absent it, /internal/_reset
# is 404 on every method, so the container has no reset endpoint at all — the
# harness sets the variable when it runs app.js directly on loopback, and the
# engine could not use the route in either case (it needs loopback AND a header
# no clinkz code path sends).

EXPOSE 8095

# A container that starts is not a target that answers.
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
    CMD node -e "require('node:http').get('http://127.0.0.1:8095/api/v2/profile',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "/app/app.js"]
