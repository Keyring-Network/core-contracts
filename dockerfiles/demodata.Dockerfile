FROM node:16

ENV APP_ROOT /app

RUN mkdir ${APP_ROOT}

COPY ./tasks ${APP_ROOT}/tasks
COPY ./contracts ${APP_ROOT}/contracts

COPY ./constants.ts ${APP_ROOT}/constants.ts
COPY ./hardhat.config.ts ${APP_ROOT}/hardhat.config.ts
COPY ./tsconfig.json ${APP_ROOT}/tsconfig.json
COPY ./package.json ${APP_ROOT}/package.json
COPY ./bin/ ${APP_ROOT}/bin/

# add the deploy keys
WORKDIR ${APP_ROOT}

RUN yarn install
RUN yarn typechain

RUN apt update && apt install -y awscli

EXPOSE 8545

SHELL ["/bin/bash", "-c"]

RUN ["chmod", "-R", "+x", "bin/"]
ENTRYPOINT bin/entrypoint.sh