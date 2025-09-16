# utils/network_utils.py
import socket

def is_domain_pointed_to_server(domain: str, server_ips: list[str]) -> bool:
    """
    Checks if the provided domain resolves to any of the server IP addresses.
    Returns True if any match found, False otherwise.
    """
    try:
        resolved_ips = socket.gethostbyname_ex(domain)[2]
        return any(ip in server_ips for ip in resolved_ips)
    except Exception:
        return False
