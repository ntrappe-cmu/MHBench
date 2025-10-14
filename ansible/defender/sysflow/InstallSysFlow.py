import os
import json

from ansible.ansible_playbook import AnsiblePlaybook
from config.config import Config

PIPELINE_PATH = os.path.join(os.path.dirname(__file__), "pipeline.local.json")
PIPELINE_TEMPLATE_PATH = os.path.join(
    os.path.dirname(__file__), "pipeline_template.local.json"
)


class InstallSysFlow(AnsiblePlaybook):
    def __init__(self, hosts: str | list[str], config: Config) -> None:
        self.name = "defender/sysflow/install_sysflow.yml"
        self.params = {"host": hosts}

        # Read template file
        with open(PIPELINE_TEMPLATE_PATH, "r") as f:
            pipeline_template = json.load(f)

        for processor in pipeline_template["pipeline"]:
            if processor["processor"] == "exporter":
                processor["es.addresses"] = (
                    "https://"
                    + config.external_ip
                    + ":"
                    + str(config.elastic_config.port)
                )
                processor["es.username"] = "elastic"
                processor["es.password"] = config.elastic_config.api_key
                processor["es.index"] = "sysflow"

        # Write to pipeline.local.json
        with open(PIPELINE_PATH, "w") as f:
            json.dump(pipeline_template, f)
