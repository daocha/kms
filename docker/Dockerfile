FROM python:3.6.6-alpine3.8

LABEL Dcha KMS "Ray LI <ray@daocha.me>"

ENV FLASK_ENV="docker" \
	FLASK_APP="main.py"

EXPOSE 5000

# COPY source files
COPY ./kms /app/kms

RUN apk add --no-cache bash gcc build-base libffi-dev && \
		pip3 install -r /app/kms/requirements.txt

WORKDIR /app/kms

CMD ["python3", "-m", "flask", "run", "--host", "0.0.0.0", "--port", "5000"]
