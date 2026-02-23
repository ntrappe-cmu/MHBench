"""
MulVAL Fact Exporter for MHBench

Walks a NetworkTopology object and emits a MulVAL-compatible input.P file
containing Prolog facts that describe the environment.

Usage:
    from src.mulval_exporter import emit_mulval_facts
    from src.models import NetworkTopology

    topology = NetworkTopology(**json_data)
    facts_string = emit_mulval_facts(topology)

    with open("input.P", "w") as f:
        f.write(facts_string)

The interaction_rules.P file is static and ships unchanged with MHBench.
Only input.P (the facts file) is generated per-environment.
"""

from typing import List, Set, Tuple, Optional
from src.models.network import NetworkTopology, Host, Subnet
from src.models.vulnerabilities import Vulnerability
from src.models.enums import VulnerabilityType


# =============================================================================
# Vulnerability Lookup Table
# =============================================================================
# Maps MHBench playbook paths to MulVAL predicate attributes.
#
# This is the only piece that requires manual maintenance. When a new
# vulnerability type is added to MHBench (in src/models/vulnerabilities.py),
# a corresponding entry must be added here.
#
# Fields:
#   vuln_id:     Prolog atom or quoted string used in vulExists/vulProperty
#   program:     The software program name MulVAL associates the vuln with
#   range:       "remoteExploit" or "localExploit"
#   consequence: What the exploit achieves (typically "privEscalation")
#   protocol:    Network protocol (only for remote exploits, None for local)
#   port:        Port number (only for remote exploits, None for local)
#
# NOTE: If a playbook_path is encountered that isn't in this table, the
# exporter will print a warning and skip that vulnerability. This means
# MulVAL's analysis will be incomplete but not incorrect.

VULN_LOOKUP = {
    # --- Lateral Movement (remote exploits) ---
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
    # --- Privilege Escalation (local exploits) ---
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


# =============================================================================
# Helper: Sanitize host names for Prolog
# =============================================================================
# MulVAL uses Prolog atoms. Atoms starting with lowercase or containing only
# alphanumeric + underscore are safe unquoted. MHBench host names like
# "host_0_subnet_0" are already safe. We just need to make sure nothing
# weird slips through.

def _prolog_atom(name: str) -> str:
    """Ensure a string is a safe Prolog atom.
    
    MHBench names (host_0_subnet_0, etc.) are already safe.
    If a name starts with uppercase or contains special chars, quote it.
    """
    if not name:
        return "''"
    # Prolog atoms starting with lowercase and containing only [a-z0-9_] are safe
    if name[0].islower() and all(c.isalnum() or c == '_' for c in name):
        return name
    # Otherwise, wrap in single quotes
    return f"'{name}'"


# =============================================================================
# Helper: Build subnet lookup structures
# =============================================================================

def _build_subnet_host_map(topology: NetworkTopology) -> dict:
    """Build a mapping from subnet name to list of Host objects.
    
    We need this for hacl generation — given a subnet name from
    subnet_connections, we need to find all hosts in that subnet.
    """
    subnet_hosts = {}
    for network in topology.networks:
        for subnet in network.subnets:
            subnet_hosts[subnet.name] = subnet.hosts
    return subnet_hosts


def _get_external_subnets(topology: NetworkTopology) -> List[Subnet]:
    """Find all subnets marked as external (attacker-reachable)."""
    external = []
    for network in topology.networks:
        for subnet in network.subnets:
            if subnet.external:
                external.append(subnet)
    return external


def _get_host_subnet(topology: NetworkTopology, host: Host) -> Optional[Subnet]:
    """Find which subnet a host belongs to."""
    for network in topology.networks:
        for subnet in network.subnets:
            for h in subnet.hosts:
                if h.id == host.id:
                    return subnet
    return None


# =============================================================================
# Namespace usernames to avoid cross-host identity collision
# =============================================================================
# MulVAL treats hasAccount(user_0, hostA, user) and hasAccount(user_0, hostB, user)
# as the SAME principal. MHBench's generic usernames (user_0, user_1) are different
# people on different hosts. We namespace non-root usernames to prevent MulVAL
# from inferring false lateral movement via principal compromise.
#
# root stays as "root" because MulVAL's rules specifically reference it.

def _namespace_username(username: str, host_name: str) -> str:
    """Namespace a username to a specific host.
    
    root → root  (MulVAL rules reference 'root' specifically)
    user_0 on host_0_subnet_0 → user_0_host_0_subnet_0
    """
    if username == "root":
        return "root"
    return f"{username}_{host_name}"


# =============================================================================
# Main Export Function
# =============================================================================

def emit_mulval_facts(topology: NetworkTopology) -> str:
    """Walk a NetworkTopology object and emit MulVAL Prolog facts.
    
    Args:
        topology: A fully constructed NetworkTopology (loaded from JSON
                  or built by SimpleNetworkGenerator).
    
    Returns:
        A string containing valid MulVAL Prolog facts (the contents of input.P).
    
    Warnings are printed to stderr for vulnerabilities that can't be mapped.
    """
    facts: List[str] = []
    # Track vulProperty facts to deduplicate (emit once globally, not per-host)
    vuln_properties_seen: Set[Tuple[str, str, str]] = set()
    # Track warnings for unmapped vulnerabilities
    warnings: List[str] = []

    # Pre-build lookup structures
    subnet_hosts = _build_subnet_host_map(topology)
    external_subnets = _get_external_subnets(topology)

    # -----------------------------------------------------------------
    # Step 1: Attacker location
    # -----------------------------------------------------------------
    # The attacker is always external ("internet") in MHBench.
    facts.append("/* Attacker location */")
    facts.append("attackerLocated(internet).")
    facts.append("")

    # -----------------------------------------------------------------
    # Step 2: Goals
    # -----------------------------------------------------------------
    # Each MHBench goal becomes an attackGoal(execCode(host, user)).
    # We resolve the target host name from the goal's target_host_id.
    facts.append("/* Attack goals */")
    for goal in topology.goals:
        # Resolve host name from target_host_id
        target_host = topology.get_host_by_id(goal.target_host_id)
        if target_host is None:
            warnings.append(f"Goal references unknown host ID: {goal.target_host_id}")
            continue

        # Determine target user
        # JSONDataExfiltrationGoal has .host_user (username string)
        # We use execCode(host, user) — if goal wants root access, use root
        target_username = getattr(goal, 'host_user', None)
        if target_username is None:
            # Fall back to root
            target_username = "root"

        # Namespace the username (root stays root)
        namespaced_user = _namespace_username(target_username, target_host.name)

        host_atom = _prolog_atom(target_host.name)
        user_atom = _prolog_atom(namespaced_user)
        facts.append(f"attackGoal(execCode({host_atom}, {user_atom})).")

    facts.append("")

    # -----------------------------------------------------------------
    # Step 3: User accounts
    # -----------------------------------------------------------------
    # For each host, for each user, emit hasAccount.
    # Permission level: is_admin=True → root, else → user
    facts.append("/* User accounts */")
    for network in topology.networks:
        for subnet in network.subnets:
            for host in subnet.hosts:
                host_atom = _prolog_atom(host.name)
                for user in host.users:
                    namespaced = _namespace_username(user.username, host.name)
                    user_atom = _prolog_atom(namespaced)
                    perm = "root" if user.is_admin else "user"
                    facts.append(
                        f"hasAccount({user_atom}, {host_atom}, {perm})."
                    )
    facts.append("")

    # -----------------------------------------------------------------
    # Step 4: Network reachability (hacl)
    # -----------------------------------------------------------------
    facts.append("/* Network reachability */")

    # 4a: Self-reachability — every host can reach itself
    for network in topology.networks:
        for subnet in network.subnets:
            for host in subnet.hosts:
                h = _prolog_atom(host.name)
                facts.append(f"hacl({h}, {h}, _, _).")

    # 4b: Intra-subnet — hosts within the same subnet can reach each other
    for network in topology.networks:
        for subnet in network.subnets:
            hosts = subnet.hosts
            for i, host_a in enumerate(hosts):
                for j, host_b in enumerate(hosts):
                    if i != j:
                        a = _prolog_atom(host_a.name)
                        b = _prolog_atom(host_b.name)
                        facts.append(f"hacl({a}, {b}, _, _).")

    # 4c: Cross-subnet — based on subnet_connections
    for conn in topology.subnet_connections:
        from_hosts = subnet_hosts.get(conn.from_subnet, [])
        to_hosts = subnet_hosts.get(conn.to_subnet, [])

        # Forward direction
        for host_from in from_hosts:
            for host_to in to_hosts:
                a = _prolog_atom(host_from.name)
                b = _prolog_atom(host_to.name)
                facts.append(f"hacl({a}, {b}, _, _).")

        # Reverse direction if bidirectional
        if conn.bidirectional:
            for host_to in to_hosts:
                for host_from in from_hosts:
                    a = _prolog_atom(host_to.name)
                    b = _prolog_atom(host_from.name)
                    facts.append(f"hacl({a}, {b}, _, _).")

    # 4d: Internet to external subnet hosts
    for subnet in external_subnets:
        for host in subnet.hosts:
            h = _prolog_atom(host.name)
            facts.append(f"hacl(internet, {h}, _, _).")

    facts.append("")

    # -----------------------------------------------------------------
    # Step 5: Vulnerabilities
    # -----------------------------------------------------------------
    # For each host's vulnerability, look up the playbook path in VULN_LOOKUP
    # and emit vulExists + networkServiceInfo (for remote) facts.
    # Collect vulProperty tuples for deduplication in Step 6.
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
                        # Unknown vulnerability — warn and skip
                        warnings.append(
                            f"No MulVAL mapping for playbook: {vuln.playbook_path} "
                            f"(on host {host.name}). Skipping."
                        )
                        continue

                    vuln_id = mapping["vuln_id"]
                    program = mapping["program"]
                    range_ = mapping["range"]
                    consequence = mapping["consequence"]

                    # vulExists: this host has this vulnerability
                    facts.append(
                        f"vulExists({host_atom}, {vuln_id}, {program})."
                    )

                    # Collect for deduplication (Step 6)
                    vuln_properties_seen.add((vuln_id, range_, consequence))

                    # networkServiceInfo: only for remote exploits
                    # These expose a network service that the attacker reaches via hacl
                    if range_ == "remoteExploit":
                        protocol = mapping["protocol"]
                        port = mapping["port"]

                        # Determine which user the service runs as.
                        # Use vuln.to_user from the JSON if available,
                        # otherwise fall back to root.
                        service_user = vuln.to_user if vuln.to_user else "root"
                        # Namespace the service user
                        namespaced_svc_user = _namespace_username(
                            service_user, host.name
                        )
                        svc_user_atom = _prolog_atom(namespaced_svc_user)

                        facts.append(
                            f"networkServiceInfo({host_atom}, {program}, "
                            f"{protocol}, {port}, {svc_user_atom})."
                        )

    facts.append("")

    # -----------------------------------------------------------------
    # Step 6: Deduplicated vulnerability properties
    # -----------------------------------------------------------------
    # vulProperty describes what a vulnerability does — it's global, not
    # per-host. We emit each unique (vuln_id, range, consequence) once.
    facts.append("/* Vulnerability properties (deduplicated) */")
    for vuln_id, range_, consequence in sorted(vuln_properties_seen):
        facts.append(f"vulProperty({vuln_id}, {range_}, {consequence}).")

    facts.append("")

    # -----------------------------------------------------------------
    # Print warnings
    # -----------------------------------------------------------------
    if warnings:
        import sys
        print("=== MulVAL Export Warnings ===", file=sys.stderr)
        for w in warnings:
            print(f"  WARNING: {w}", file=sys.stderr)
        print(f"  Total: {len(warnings)} warning(s)", file=sys.stderr)

    return "\n".join(facts)


# =============================================================================
# Convenience: export to file
# =============================================================================

def export_mulval_facts_to_file(
    topology: NetworkTopology,
    output_path: str,
) -> None:
    """Write MulVAL facts to a file.
    
    Args:
        topology: A fully constructed NetworkTopology.
        output_path: Path to write the input.P file.
    """
    facts = emit_mulval_facts(topology)
    with open(output_path, "w") as f:
        f.write(facts)
    print(f"MulVAL facts written to: {output_path}")
