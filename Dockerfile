# FROM public.ecr.aws/lambda/python:3.9-x86_64 as lambda-dep
#
# FROM python:3.9-slim-bullseye
#
# RUN apt update \
# && apt upgrade \
# && apt install curl -y \
# && apt install libcurl4-openssl-dev libssl-dev gcc -y
#
# COPY --from=lambda-dep /lambda-entrypoint.sh /
# COPY --from=lambda-dep /usr/local/bin/aws-lambda-rie /usr/local/bin/aws-lambda-rie
# COPY --from=lambda-dep /opt /opt
# COPY --from=lambda-dep /var/runtime/bootstrap var/runtime/bootstrap
#
# ENV LANG=en_US.UTF-8
# ENV TZ=:/etc/localtime
# ENV PATH=${PATH}/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin
# ENV LD_LIBRARY_PATH=/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib
# ENV LAMBDA_TASK_ROOT=/var/task
# ENV LAMBDA_RUNTIME_DIR=/var/runtime
#
# WORKDIR /var/task
#
# COPY src/ ${LAMBDA_TASK_ROOT}
# RUN pip install -r ./requirements.txt -t ${LAMBDA_TASK_ROOT}
#
# # CMD ["python", "./lambda_function.py"]
#
# # ENTRYPOINT [ "/usr/local/bin/python", "lambda_function.py" ]
# # CMD [ "app.handler" ]
#
# ENTRYPOINT ["/lambda-entrypoint.sh"]
# CMD ["lambda_function.lambda_handler"]


# Define custom function directory
ARG FUNCTION_DIR="/function"

FROM public.ecr.aws/docker/library/python:buster as build-image

# Include global arg in this stage of the build
ARG FUNCTION_DIR

# Install aws-lambda-cpp build dependencies
RUN apt-get update && \
  apt-get install -y \
  g++ \
  make \
  cmake \
  unzip \
  libcurl4-openssl-dev \
  apt curl \
  libcurl4-openssl-dev libssl-dev gcc

# Copy function code
RUN mkdir -p ${FUNCTION_DIR}
COPY src/* ${FUNCTION_DIR}/

# Install the function's dependencies
RUN pip install \
    --target ${FUNCTION_DIR} \
    -r ${FUNCTION_DIR}/requirements.txt


FROM public.ecr.aws/docker/library/python:buster

# Include global arg in this stage of the build
ARG FUNCTION_DIR
# Set working directory to function root directory
WORKDIR ${FUNCTION_DIR}

# Copy in the built dependencies
COPY --from=build-image ${FUNCTION_DIR} ${FUNCTION_DIR}

ENTRYPOINT [ "/usr/local/bin/python", "-m", "awslambdaric" ]
CMD [ "lambda_function.lambda_handler" ]