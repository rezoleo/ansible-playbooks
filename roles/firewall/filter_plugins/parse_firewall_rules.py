import re
from typing import Dict, List

from ansible.errors import AnsibleFilterError
from ansible.utils.display import Display

regName = re.compile(r'\d{3}-\w+')

# Build a single rule
def parse_rule(rule: Dict[str, any]) -> str:
    # Check that the rule is a dict
    if type(rule) != dict:
        raise AnsibleFilterError("Rules should be a dictionary!")
    # If the argument raw-rule is present it defines completely the rule
    if "raw-rule" in rule:
        return rule["raw-rule"]
    builder = []
    if "chain" not in rule:
        raise AnsibleFilterError("The rule does not have a 'chain' key!")
    if "target" not in rule:
        raise AnsibleFilterError("The rule does not have a 'target' key!")
    builder.extend(["-A", rule["chain"]])
    if "protocol" in rule:
        if rule["protocol"].lower() in ["tcp", "udp", "icmp", "all"]:
            builder.extend(["--protocol", rule["protocol"]])
        else:
            raise AnsibleFilterError("The protocol \"%s\" is not supported!" % rule["protocol"])
    if "source" in rule:
        builder.extend(["--source", rule["source"]])
    if "destination" in rule:
        builder.extend(["--destination", rule["destination"]])
    if "source-ipset" in rule:
        builder.extend(["--match set --set", rule["source-ipset"], "src"])
    if "destination-port" in rule:
        builder.extend(["--match set --set", rule["destination-port"], "dst"])
    if "destination-port" in rule:
        if "protocol" in rule and rule["protocol"].lower() in ["tcp", "udp"]:
            builder.extend(["--destination-port", str(rule["destination-port"])])
        else:
            raise AnsibleFilterError("\"destination-port\" should be used with tcp or udp!")
    builder.extend(["--jump", rule["target"]])
    if "comment" in rule:
        builder.extend(["--match comment --comment", "\"" + rule["comment"] + "\""])
    else:
        Display().warning("There are no comment present on the rule \"%s\"!" % rule)
    if "raw-extras" in rule:
        if type(rule["raw-extras"]) == list:
            builder.extend(rule["raw-extras"])
        elif type(rule["raw-extras"]) == str:
            builder.append(rule["raw-extras"])
        else:
            raise AnsibleFilterError("The extras should be a list or a string!")

    return " ".join(builder)

def parse_firewall_rules(rule_set: Dict[str, list]) -> Dict[str, list]:
    # Check that the rule_set is a dict.
    if type(rule_set) != dict:
        raise AnsibleFilterError("The rule sets must be a dictionary!")

    parsed_rule_set = {}

    for name, rules in rule_set.items():
        # Check that the rules are defined as a list.
        if type(rules) != list:
            raise AnsibleFilterError("%s should contain a list of rules!" % name)
        # Check that the name of the rule set is formated correctly. Should be like 000-base.
        if not regName.match(name):
            raise AnsibleFilterError("%s is not a valid rule set name. Rule set name should match pattern '\\d{3}-\\w+'!" % name)
        parsed_rules = []
        # Loop on all rules to translate them into iptables rules.
        for rule in rules:
            # We want to add some information if the underlying function except.
            try:
                parsed_rules.append(parse_rule(rule))
            except AnsibleFilterError as err:
                raise AnsibleFilterError("Rule \"%s\" in %s is invalid! %s" % (rule, name, err.message))
        # Add the parsed rule in the dict to be returned.
        parsed_rule_set[name] = parsed_rules

    return parsed_rule_set

class FilterModule(object):
    def filters(self):
        return {
            'parse_firewall_rules':parse_firewall_rules
        }
