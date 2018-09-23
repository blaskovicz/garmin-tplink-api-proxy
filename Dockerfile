FROM node:8-alpine
EXPOSE 3095
WORKDIR /home/node
USER node:node
COPY --chown=node:node . .
ENV LOG_LEVEL=info \
    PORT=3095 \
    REDIS_URL=redis://:password@host:port/db \
    CLIENT_ID_TO_SECRET='{"foo_id":"bar_secret"}' \
    CRYPTO_SECRET=feedbeef \
    NODE_ENV=development
RUN yarn install && \
    yarn lint && \
    yarn build
CMD yarn start