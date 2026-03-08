import json
import re
from typing import Any

from ansible.errors import AnsibleFilterError
from ansible.utils.display import Display

rule_name = re.compile(r'\d{3}-\w+')

allowed_protocols = ["tcp", "udp", "icmp", "all"]

# Build a single rule
def parse_firewall_rule(rule: dict[str, Any]) -> str:
    keys = list(rule.keys())
    # Check that the rule is a dict
    if not isinstance(rule, dict):
        raise AnsibleFilterError(f"The rule \"{rule}\" should be a dictionary!")

    # If the argument raw_rule is present it defines completely the rule
    if "raw_rule" in rule:
        return rule["raw_rule"]

    if not "rule_name" in rule:
        raise AnsibleFilterError(f"The rule  \"{rule}\" must have a name (a \"rule_name\" key)!")
    rule_name = rule["rule_name"]
    rule.pop("rule_name")

    if "chain" not in rule:
        raise AnsibleFilterError(f"The rule \"{rule_name}\" must have a 'chain' key!")
    if "target" not in rule:
        raise AnsibleFilterError(f"The rule \"{rule_name}\" must have a 'target' key!")
    builder = ["-A", rule["chain"]]
    rule.pop("chain")

    if "protocol" in rule:
        if rule["protocol"].lower() in allowed_protocols:
            builder.extend(["--protocol", rule["protocol"]])
            if "destination_port" in rule:
                if rule["protocol"].lower() in ["tcp", "udp"]:
                    builder.extend(["--destination-port", str(rule["destination_port"])])
                    rule.pop("destination_port")
                else:
                    raise AnsibleFilterError(f"The rule \"{rule_name}\" should not contain a 'destination_port' key. 'destination_port' should be used with tcp or udp!")
            rule.pop("protocol")
        else:
            raise AnsibleFilterError(f"The protocol \"{rule["protocol"]}\" in rule \"{rule_name}\" is not a valid protocol! Allowed protocols are {", ".join(allowed_protocols)}.")

    if "source" in rule:
        builder.extend(["--source", rule["source"]])
        rule.pop("source")

    if "destination" in rule:
        builder.extend(["--destination", rule["destination"]])
        rule.pop("destination")

    if "source_ipset" in rule:
        builder.extend(["--match set --set", rule["source_ipset"], "src"])
        rule.pop("source_ipset")

    if "destination_ipset" in rule:
        builder.extend(["--match set --set", rule["destination_ipset"], "dst"])
        rule.pop("destination_ipset")

    builder.extend(["--jump", rule["target"]])
    rule.pop("target")

    builder.extend(["--match comment --comment", json.dumps(rule_name)])

    if "raw_extras" in rule:
        if isinstance(rule["raw_extras"], list):
            builder.extend(rule["raw_extras"])
        elif isinstance(rule["raw_extras"], str):
            builder.append(rule["raw_extras"])
        else:
            raise AnsibleFilterError(f"The extras in rule \"{rule_name}\" should be a list or a string!")
        rule.pop("raw_extras")

    if len(rule) != 0:
        raise AnsibleFilterError(f"Unrecognized {"property" if len(rule) == 1 else "properties"} in rule \"{rule_name}\": {", ".join(list(rule.keys()))}.")

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
