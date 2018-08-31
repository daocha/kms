from flask import Flask
from flask import jsonify
from kms.endpoint.keyring import keyring_api
import logging.config
import json

with open('logging.json') as f:
    config_dict = json.load(f)
    logging.config.dictConfig(config_dict)

app = Flask(__name__)
app.register_blueprint(keyring_api, url_prefix=('/kms'))

if __name__ == '__main__':
    app.run()
