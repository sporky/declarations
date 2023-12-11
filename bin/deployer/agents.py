from .models import *
from pathlib import Path
import json
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from time import sleep

urllib3.disable_warnings(InsecureRequestWarning)


def load_target_file(targetfile):
    with open(targetfile, "r") as fh:
        targets = json.load(fh)
        return Targets(**targets)


def find_target_files(basedir):
    target_files = Path(basedir).glob("*/target.json")
    for t in target_files:
        print(f"Found {t}")
        targets = load_target_file(t)
        print(f"targets: {targets}")
        d = WAFDeploy(targets)
        d.update_policy()
        d.check_policy()
        d.activate_policy()


class WAFDeploy:
    def __init__(self, targets: Targets):
        self.targets = targets
        self.s = requests.Session()
        self.s.verify = False

    def _import_body(self):
        return {
            "fileReference": {"link": f"{self.targets.bigip.waf_policy}"},
            "policy": {"fullPath": f"{self.targets.bigip.waf_policy_name}"},
        }

    def _apply_body(self):
        return {"policy": {"fullPath": f"{self.targets.bigip.waf_policy_name}"}}

    def update_policy(self):
        print("\nupdating policy")
        body = json.dumps(self._import_body())
        print(f"\n{body}\n")
        url = f"https://{self.targets.bigip.hostname}/mgmt/tm/asm/tasks/import-policy"
        self.s.auth = (self.targets.bigip.username, self.targets.bigip.password)
        r = self.s.post(url=url, data=body)
        print(f"update policy response: {r.text}")
        sleep(5)

    def check_policy(self):
        print("\nchecking policy")
        url = f"https://{self.targets.bigip.hostname}/mgmt/tm/asm/tasks/import-policy"
        r = self.s.get(url=url)
        print(f"check policy response: {r.text}")
        sleep(5)

    def activate_policy(self):
        print("\nactivating policy")
        body = json.dumps(self._import_body())
        print(f"\n{body}\n")
        url = f"https://{self.targets.bigip.hostname}/mgmt/tm/asm/tasks/apply-policy"
        r = self.s.post(url=url, data=body)
        print(f"apply policy response: {r.text}")
        sleep(5)
