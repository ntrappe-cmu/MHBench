"""
Test script for mulval_exporter.py

Loads generated_network_0.json and runs the exporter to produce input.P.
Since we don't have the full MHBench package installed, this script
reconstructs just enough of the model structure from the raw JSON to
exercise the exporter logic.

Run:  python test_exporter.py
"""

import json
import sys
import os

# ---------------------------------------------------------------------------
# Minimal stand-in classes that mirror the Pydantic models' field access.
# These let us test the exporter without installing MHBench.
# In the real integration, you'd just use:
#   from src.models import NetworkTopology
#   topology = NetworkTopology(**data)
# ---------------------------------------------------------------------------

class FakeObj:
    """Generic attribute-bag built from a dict."""
    def __init__(self, d: dict):
        for k, v in d.items():
            if isinstance(v, dict):
                setattr(self, k, FakeObj(v))
            elif isinstance(v, list):
                setattr(self, k, [FakeObj(i) if isinstance(i, dict) else i for i in v])
            else:
                setattr(self, k, v)


class FakeTopology:
    """Mimics NetworkTopology with just enough to run the exporter."""
    def __init__(self, data: dict):
        # networks → list of FakeNetwork
        self.networks = []
        for net_data in data.get("networks", []):
            net = FakeObj({"name": net_data["name"], "subnets": []})
            for sub_data in net_data.get("subnets", []):
                subnet = FakeObj({
                    "name": sub_data["name"],
                    "external": sub_data.get("external", False),
                    "hosts": [],
                })
                for host_data in sub_data.get("hosts", []):
                    host = FakeObj({
                        "id": host_data["id"],
                        "name": host_data["name"],
                        "ip_address": host_data.get("ip_address"),
                        "users": [FakeObj(u) for u in host_data.get("users", [])],
                        "vulnerabilities": [FakeObj(v) for v in host_data.get("vulnerabilities", [])],
                    })
                    subnet.hosts.append(host)
                net.subnets.append(subnet)
            self.networks.append(net)

        # subnet_connections
        self.subnet_connections = [FakeObj(c) for c in data.get("subnet_connections", [])]

        # goals
        self.goals = [FakeObj(g) for g in data.get("goals", [])]

        # attacker_host
        ah = data.get("attacker_host")
        self.attacker_host = FakeObj(ah) if ah else None

    def get_host_by_id(self, host_id):
        """Lookup host by UUID string."""
        for network in self.networks:
            for subnet in network.subnets:
                for host in subnet.hosts:
                    if host.id == host_id:
                        return host
        # Also check attacker host
        if self.attacker_host and self.attacker_host.id == host_id:
            return self.attacker_host
        return None

    def get_all_hosts(self, include_attacker=False):
        hosts = []
        for network in self.networks:
            for subnet in network.subnets:
                hosts.extend(subnet.hosts)
        if include_attacker and self.attacker_host:
            hosts.append(self.attacker_host)
        return hosts


# ---------------------------------------------------------------------------
# Import the exporter — but patch it to work with our fake objects.
# The exporter only uses attribute access (.name, .hosts, .vulnerabilities, etc.)
# and topology.get_host_by_id(), so our fakes are sufficient.
# ---------------------------------------------------------------------------

# Add parent dir to path so we can import mulval_exporter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# We need to provide the VULN_LOOKUP and helper functions.
# Rather than importing from mulval_exporter.py (which imports src.models),
# we inline the core logic here for testing. In real MHBench, you'd just
# import and call emit_mulval_facts(topology).

# Copy VULN_LOOKUP from the exporter
VULN_LOOKUP = {
    "vulnerabilities/apacheStruts/setupStruts.yml": {
        "vuln_id": "'CVE-2017-5638'",
        "program": "httpd",
        "range": "remoteExploit",
        "consequence": "privEscalation",
        "protocol": "tcp",
        "port": 8080,
    },
    "vulnerabilities/NetcatShell.yml": {
        "vuln_id": "netcatBackdoor",
        "program": "netcat",
        "range": "remoteExploit",
        "consequence": "privEscalation",
        "protocol": "tcp",
        "port": 4444,
    },
    "deployment_instance/setup_server_ssh_keys/setup_ssh_keys.yml": {
        "vuln_id": "sshKeyMisconfig",
        "program": "sshd",
        "range": "remoteExploit",
        "consequence": "privEscalation",
        "protocol": "tcp",
        "port": 22,
    },
    "vulnerabilities/privledge_escalation/sudobaron/sudobaron.yml": {
        "vuln_id": "'CVE-2021-3156'",
        "program": "sudo",
        "range": "localExploit",
        "consequence": "privEscalation",
        "protocol": None,
        "port": None,
    },
    "vulnerabilities/privledge_escalation/writeablePasswd/writeablePasswd.yml": {
        "vuln_id": "writeablePasswd",
        "program": "kernel",
        "range": "localExploit",
        "consequence": "privEscalation",
        "protocol": None,
        "port": None,
    },
}


def _prolog_atom(name):
    if not name:
        return "''"
    if name[0].islower() and all(c.isalnum() or c == '_' for c in name):
        return name
    return f"'{name}'"


def _namespace_username(username, host_name):
    if username == "root":
        return "root"
    return f"{username}_{host_name}"


def emit_mulval_facts_standalone(topology):
    """Standalone version of emit_mulval_facts for testing without MHBench imports."""
    facts = []
    vuln_properties_seen = set()
    warnings = []

    # Build subnet → hosts map
    subnet_hosts = {}
    external_subnets = []
    for network in topology.networks:
        for subnet in network.subnets:
            subnet_hosts[subnet.name] = subnet.hosts
            if subnet.external:
                external_subnets.append(subnet)

    # Step 1: Attacker
    facts.append("/* Attacker location */")
    facts.append("attackerLocated(internet).")
    facts.append("")

    # Step 2: Goals
    facts.append("/* Attack goals */")
    for goal in topology.goals:
        target_host = topology.get_host_by_id(goal.target_host_id)
        if target_host is None:
            warnings.append(f"Goal references unknown host ID: {goal.target_host_id}")
            continue
        target_username = getattr(goal, 'host_user', None) or "root"
        namespaced_user = _namespace_username(target_username, target_host.name)
        host_atom = _prolog_atom(target_host.name)
        user_atom = _prolog_atom(namespaced_user)
        facts.append(f"attackGoal(execCode({host_atom}, {user_atom})).")
    facts.append("")

    # Step 3: Accounts
    facts.append("/* User accounts */")
    for network in topology.networks:
        for subnet in network.subnets:
            for host in subnet.hosts:
                host_atom = _prolog_atom(host.name)
                for user in host.users:
                    namespaced = _namespace_username(user.username, host.name)
                    user_atom = _prolog_atom(namespaced)
                    perm = "root" if user.is_admin else "user"
                    facts.append(f"hasAccount({user_atom}, {host_atom}, {perm}).")
    facts.append("")

    # Step 4: hacl
    facts.append("/* Network reachability */")

    # 4a: Self
    for network in topology.networks:
        for subnet in network.subnets:
            for host in subnet.hosts:
                h = _prolog_atom(host.name)
                facts.append(f"hacl({h}, {h}, _, _).")

    # 4b: Intra-subnet
    for network in topology.networks:
        for subnet in network.subnets:
            hosts = subnet.hosts
            for i, ha in enumerate(hosts):
                for j, hb in enumerate(hosts):
                    if i != j:
                        facts.append(f"hacl({_prolog_atom(ha.name)}, {_prolog_atom(hb.name)}, _, _).")

    # 4c: Cross-subnet
    for conn in topology.subnet_connections:
        from_hosts = subnet_hosts.get(conn.from_subnet, [])
        to_hosts = subnet_hosts.get(conn.to_subnet, [])
        for hf in from_hosts:
            for ht in to_hosts:
                facts.append(f"hacl({_prolog_atom(hf.name)}, {_prolog_atom(ht.name)}, _, _).")
        if conn.bidirectional:
            for ht in to_hosts:
                for hf in from_hosts:
                    facts.append(f"hacl({_prolog_atom(ht.name)}, {_prolog_atom(hf.name)}, _, _).")

    # 4d: Internet → external
    for subnet in external_subnets:
        for host in subnet.hosts:
            facts.append(f"hacl(internet, {_prolog_atom(host.name)}, _, _).")
    facts.append("")

    # Step 5: Vulnerabilities
    facts.append("/* Vulnerabilities and services */")
    for network in topology.networks:
        for subnet in network.subnets:
            for host in subnet.hosts:
                if not host.vulnerabilities:
                    continue
                host_atom = _prolog_atom(host.name)
                facts.append(f"/* {host.name} */")
                for vuln in host.vulnerabilities:
                    mapping = VULN_LOOKUP.get(vuln.playbook_path)
                    if mapping is None:
                        warnings.append(
                            f"No MulVAL mapping for: {vuln.playbook_path} (on {host.name})"
                        )
                        continue

                    vuln_id = mapping["vuln_id"]
                    program = mapping["program"]
                    range_ = mapping["range"]
                    consequence = mapping["consequence"]

                    facts.append(f"vulExists({host_atom}, {vuln_id}, {program}).")
                    vuln_properties_seen.add((vuln_id, range_, consequence))

                    if range_ == "remoteExploit":
                        protocol = mapping["protocol"]
                        port = mapping["port"]
                        service_user = vuln.to_user if vuln.to_user else "root"
                        namespaced_svc = _namespace_username(service_user, host.name)
                        svc_atom = _prolog_atom(namespaced_svc)
                        facts.append(
                            f"networkServiceInfo({host_atom}, {program}, "
                            f"{protocol}, {port}, {svc_atom})."
                        )
    facts.append("")

    # Step 6: Deduplicated vulProperty
    facts.append("/* Vulnerability properties (deduplicated) */")
    for vuln_id, range_, consequence in sorted(vuln_properties_seen):
        facts.append(f"vulProperty({vuln_id}, {range_}, {consequence}).")
    facts.append("")

    # Warnings
    if warnings:
        print("=== MulVAL Export Warnings ===", file=sys.stderr)
        for w in warnings:
            print(f"  WARNING: {w}", file=sys.stderr)

    return "\n".join(facts)


# ---------------------------------------------------------------------------
# Main: Load JSON, build fake topology, run exporter
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Find the JSON file
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_topology.json")
    if not os.path.exists(json_path):
        print(f"ERROR: Cannot find {json_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading topology from: {json_path}", file=sys.stderr)

    with open(json_path, "r") as f:
        data = json.load(f)

    topology = FakeTopology(data)

    # Count what we loaded
    total_hosts = len(topology.get_all_hosts())
    total_vulns = sum(
        len(h.vulnerabilities)
        for h in topology.get_all_hosts()
    )
    total_users = sum(
        len(h.users)
        for h in topology.get_all_hosts()
    )
    print(f"Loaded: {total_hosts} hosts, {total_users} users, {total_vulns} vulnerabilities",
          file=sys.stderr)

    # Run the exporter
    output = emit_mulval_facts_standalone(topology)

    # Write to file
    output_path = "input.P"
    with open(output_path, "w") as f:
        f.write(output)

    print(f"\nMulVAL facts written to: {output_path}", file=sys.stderr)
    print(f"Total lines: {len(output.splitlines())}", file=sys.stderr)

    # Also print to stdout for inspection
    print("\n" + "=" * 60)
    print("Generated input.P:")
    print("=" * 60)
    print(output)
