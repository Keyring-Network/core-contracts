FROM node:16

ENV APP_ROOT /app

RUN mkdir ${APP_ROOT}

COPY ./tasks ${APP_ROOT}/tasks
COPY ./contracts ${APP_ROOT}/contracts

COPY ./constants.ts ${APP_ROOT}/constants.ts
COPY ./hardhat.config.ts ${APP_ROOT}/hardhat.config.ts
COPY ./tsconfig.json ${APP_ROOT}/tsconfig.json
COPY ./package.json ${APP_ROOT}/package.json
COPY ./bin/automation_demodata_deploy.sh ${APP_ROOT}/bin/automation_demodata_deploy.sh

# add the deploy keys
WORKDIR ${APP_ROOT}

RUN yarn install

RUN apt update && apt install -y awscli

EXPOSE 8545

SHELL ["/bin/bash", "-c"]

RUN ["chmod", "+x", "bin/automation_demodata_deploy.sh"]
ENTRYPOINT bin/automation_demodata_deploy.sh