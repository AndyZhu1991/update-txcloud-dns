#!/usr/bin/env python

import requests
import time
import hmac
import base64
import json
import logging


host_domain = "cns.api.qcloud.com"
api_path = "/v2/index.php"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("txcloud-dns")

with open("config.json", "r", encoding='UTF-8') as config_file:
    config = json.load(config_file)


def common_params():
    timestamp = int(time.time())
    return {
        "SecretId": config["secret_id"],
        "Timestamp": timestamp,
        "Nonce": timestamp + 1,
        "SignatureMethod": "HmacSHA256"
    }


def record_list_params():
    return {
        "Action": "RecordList",
        "domain": config["domain"]
    }


def record_modify_params(record_id, sub_domain, ip):
    return {
        "Action": "RecordModify",
        "domain": config["domain"],
        "recordId": record_id,
        "subDomain": sub_domain,
        "recordType": "A",
        "recordLine": "默认",
        "value": ip,
        "ttl": 3600
    }


def sign(params):
    items = list(params.items())
    items.sort()
    params_str = "&".join(map(lambda item: "{}={}".format(item[0], item[1]), items))
    src_str = "GET{}{}?{}".format(host_domain, api_path, params_str)
    sign = hmac.new(config["secret_key"].encode("UTF-8"), src_str.encode("UTF-8"), "SHA256")
    sign_str = base64.b64encode(sign.digest())
    sign_str = str(sign_str, encoding="utf8")
    return sign_str


def get_public_ip():
    return requests.get("http://jsonip.com").json()["ip"]


def update_dns():
    params = common_params()
    params.update(record_list_params())
    params["Signature"] = sign(params)
    record_list_result = requests.get("https://{}{}".format(host_domain, api_path), params=params).json()
    if (record_list_result["code"] != 0):
        logger.error("Get record list error: code={}, msg={}".format(record_list_result["code"], record_list_result["message"]))
        return

    ip = get_public_ip()
    logger.info("Your ip is {}".format(ip))

    for record in record_list_result["data"]["records"]:
        if record["type"] == "A" and record["name"] in config['second_domain']:
            params = common_params()
            params.update(record_modify_params(record["id"], record["name"], ip))
            params["Signature"] = sign(params)
            modify_result = requests.get("https://{}{}".format(host_domain, api_path), params=params).json()
            if (modify_result["code"] != 0):
                logger.error("Modify dns {} record error: code={}, msg={}"
                             .format(record["name"], modify_result["code"], modify_result["message"]))
            else:
                logger.info("Modify dns {} record success".format(record["name"]))


if __name__ == "__main__":
    while True:
        update_dns()
        time.sleep(config["update_interval"])
