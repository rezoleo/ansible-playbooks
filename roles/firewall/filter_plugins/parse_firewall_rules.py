import json
import re
from typing import Any

from ansible.errors import AnsibleFilterError
from ansible.utils.display import Display

rule_name = re.compile(r'\d{3}-\w+')

# Build a single rule
def parse_firewall_rule(rule: dict[str, Any]) -> str:
    # Check that the rule is a dict
    if not isinstance(rule, dict):
        raise AnsibleFilterError(f"The rule \"{rule}\" should be a dictionary!")
    # If the argument raw_rule is present it defines completely the rule
    if "raw_rule" in rule:
        return rule["raw_rule"]
    builder = []
    if "chain" not in rule:
        raise AnsibleFilterError(f"The rule \"{rule}\" must have a 'chain' key!")
    if "target" not in rule:
        raise AnsibleFilterError(f"The rule \"{rule}\" must have a 'target' key!")
    builder.extend(["-A", rule["chain"]])
    if "protocol" in rule:
        if rule["protocol"].lower() in ["tcp", "udp", "icmp", "all"]:
            builder.extend(["--protocol", rule["protocol"]])
        else:
            raise AnsibleFilterError(f"The protocol \"{rule["protocol"]}\" in rule \"{rule}\" is not a valid protocol!")
    if "source" in rule:
        builder.extend(["--source", rule["source"]])
    if "destination" in rule:
        builder.extend(["--destination", rule["destination"]])
    if "source_ipset" in rule:
        builder.extend(["--match set --set", rule["source_ipset"], "src"])
    if "destination_ipset" in rule:
        builder.extend(["--match set --set", rule["destination_ipset"], "dst"])
    if "destination_port" in rule:
        if "protocol" in rule and rule["protocol"].lower() in ["tcp", "udp"]:
            builder.extend(["--destination-port", str(rule["destination_port"])])
        else:
            raise AnsibleFilterError(f"The rule \"{rule}\" should not contain a 'destination_port' key. 'destination_port' should be used with tcp or udp!")
    builder.extend(["--jump", rule["target"]])
    if "comment" in rule:
        builder.extend(["--match comment --comment", json.dumps(rule["comment"])])
    else:
        Display().warning(f"There are no comment present on the rule \"{rule}\"! Commenting your rules is recommended.")
    if "raw_extras" in rule:
        if isinstance(rule["raw_extras"], list):
            builder.extend(rule["raw_extras"])
        elif isinstance(rule["raw_extras"], str):
            builder.append(rule["raw_extras"])
        else:
            raise AnsibleFilterError(f"The extras in rule \"{rule}\" should be a list or a string!")

    return " ".join(builder)

def validate_firewall_rules(rule_set: dict[str, list]) -> dict[str, list]:
    if not isinstance(rule_set, dict):
        raise AnsibleFilterError("The firewall rule sets must be a dictionary!")
    for name, rules in rule_set.items():
        # Check that the rules are defined as a list.
        if not isinstance(rules, list):
            raise AnsibleFilterError(f"The rule set {name} should contain a list of rules!")
        # Check that the name of the rule set is formated correctly. Should be like 000-base.
        if not rule_name.match(name):
            raise AnsibleFilterError(f"{name} is not a valid rule set name! Rule set name should match pattern {rule_name.pattern}!")
        for rule in rules:
            if not isinstance(rule, dict):
                raise AnsibleFilterError(f"The rule \"{rule}\" in {name} rule set should be a dictionary!")
    return rule_set

class FilterModule(object):
    def filters(self):
        return {
            'validate_firewall_rules':validate_firewall_rules,
            'parse_firewall_rule':parse_firewall_rule
        }
