# Date: 31 Aug 2018
# Author: Ray LI <ray@daocha.me>
""" Keyring """

from kms.common import rsa
from kms.vault import tool
from flask import Blueprint
from flask import jsonify
from flask import request
import json
import os
import logging

keyring_api = Blueprint('keyring_api', __name__)


@keyring_api.route("/load/sample", methods=["GET"])
def load_config_insure2go():
    config_json = load_config()
    return jsonify(config_json['Sample'])

@keyring_api.route("/968dfe03d8dd144628b5cec6a724b552", methods=["GET"])
def mytool():
    tool.encryptJson()
    return jsonify(test=True)


def load_config():
    logger = logging.getLogger(__name__)
    logger.info("%s is requesting configurations." % request.remote_addr)
    # decrypt
    this_dir = os.path.dirname(os.path.abspath(__file__))
    if "pri_key" not in globals():
        global pri_key
        pri_key = rsa.importDefaultPrivateKey(False)
    config = rsa.readEncryptedFile("%s/../vault/encrypted.json" % this_dir, pri_key)
    config_json = json.loads(config.decode("utf-8"))
    return config_json
