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
RUN echo '\
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n\
INFURA_API_KEY=blank\n\
' > ${APP_ROOT}/.env

WORKDIR ${APP_ROOT}

RUN yarn install

RUN npx hardhat compile

EXPOSE 8545

SHELL ["/bin/bash", "-c"]

RUN ["chmod", "+x", "bin/automation_demodata_deploy.sh"]
ENTRYPOINT bin/automation_demodata_deploy.sh