import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone

from pkg_19544.configs.constants import (
    BLACKLIST_CIPHERS,
    BLACKLIST_CONTROL_CHARACTERS,
    SOCKET_TIMEOUT,
    WHITELIST_CHARS_IN_FQDN,
    WHITELIST_HASHING_ALG,
    WHITELIST_SCHEME,
    WHITELIST_TLS_VERSION,
)
from pkg_19544.utils.err import on_false
from pkg_19544.utils.tld import get_tlds


class ValueError(ValueError):
    pass


@on_false(exception_type=ValueError, message="invalid protocol scheme prefix.")
def _has_allowed_scheme(user_url: str) -> bool:
    return True if user_url.lower().startswith(WHITELIST_SCHEME) else False


@on_false(exception_type=ValueError, message='unsupported basic auth found in URL.')
def _has_no_basic_auth(userinfo: str) -> bool:
    return True if not userinfo else False


@on_false(exception_type=ValueError, message="unsupported control character(s) found in URL.")
def _has_no_control_character(user_url: str) -> bool:
    """
    log injection (exploit CRLF vulnerability): https://owasp.org/www-community/attacks/Log_Injection
    """
    return False if any(char in user_url for char in BLACKLIST_CONTROL_CHARACTERS) else True


@on_false(exception_type=ValueError, message="invalid FQDN.")
def _has_valid_fqdn_syntax(fqdn: str) -> bool:
    """
    allowed characters: https://datatracker.ietf.org/doc/html/rfc3986#section-2
    """
    if all([
        re.fullmatch(WHITELIST_CHARS_IN_FQDN, fqdn) is not None,
        fqdn.count('.') > 0,
        len(fqdn) <= 255,
    ]):
        return True
    else:
        return False


@on_false(exception_type=ValueError, message="invalid FQDN label.")
def _has_valid_fqdn_label(fqdn: str) -> bool:
    """
    allowed characters: https://datatracker.ietf.org/doc/html/rfc3986#section-2
    allowed length    : https://datatracker.ietf.org/doc/html/rfc2181#section-11
    """
    list_split_fqdn = fqdn.split('.')
    for label in list_split_fqdn:
        if any([
            not label[0].isalnum(),
            not label[-1].isalnum(),
            len(label) > 63
        ]):
            return False
    return True


@on_false(exception_type=ValueError, message="invalid top-level domain.")
def _has_valid_tld(fqdn: str) -> bool:
    """
    authoritative TLD list: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
    """
    return True if fqdn.split('.')[-1:][0].upper() in get_tlds() else False


@on_false(exception_type=ValueError, message="unsupported TLS configuration.")
def _has_valid_tls(netloc: str, fqdn: str) -> bool:
    """
    ref: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
    """
    port = int(netloc.split(":", maxsplit=1)[1]) if ":" in netloc else 443
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        with socket.create_connection((fqdn, port), timeout=SOCKET_TIMEOUT) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_name, protocol_version, _ = cipher_info

                    # only-support-strong-ciphers
                    if any(cipher in cipher_name.upper() for cipher in BLACKLIST_CIPHERS):
                        raise ValueError('URL certificate not using strong ciphers.')

                    # use-strong-cryptographic-hashing-algorithms
                    if not cipher_name.endswith(WHITELIST_HASHING_ALG):
                        raise ValueError('URL certificate not using strong hashing algorithm.')

                    # only-support-strong-protocols
                    if protocol_version not in WHITELIST_TLS_VERSION:
                        raise ValueError('URL certificate not using strong protocol.')

                    # check-certificate-expiration
                    cert_dict = ssock.getpeercert()
                    if isinstance(cert_dict, dict):
                        cert_valid_till = cert_dict.get('notAfter')
                        if isinstance(cert_valid_till, str):
                            # convert cert datetime string to become timezone-aware object and compare with datetime now
                            cert_date_format = "%b %d %H:%M:%S %Y GMT"
                            parsed_cert_datetime = datetime.strptime(cert_valid_till, cert_date_format)
                            parsed_cert_datetime_utc = parsed_cert_datetime.astimezone(timezone.utc)
                            current_datetime_utc = datetime.now(timezone.utc)
                            if parsed_cert_datetime_utc < current_datetime_utc:
                                raise ValueError('URL certificate expired')
                        else:
                            raise ValueError('invalid URL certificate ..')
                    else:
                        raise ValueError('invalid URL certificate !!')
                else:
                    raise ValueError('failed to estasblish https connection.')
            return True
    except (ssl.SSLError, socket.gaierror, socket.timeout, ConnectionRefusedError):  # pragma: no cover
        return False


@on_false(exception_type=ValueError, message="FQDN ip address is not public routable.")
def _is_fqdn_ipaddr_public_routable(scheme: str, fqdn: str) -> bool:
    """
    authoritative ipv4 list: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
    authoritative ipv6 list: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    """
    try:
        list_addr_info = socket.getaddrinfo(fqdn, scheme, family=0, type=1, proto=6, flags=socket.AI_CANONNAME)
        for addr_info in list_addr_info:
            ip_addr = ipaddress.ip_address(addr_info[4][0])
            if any([
                ip_addr.is_reserved,
                ip_addr.is_link_local,
                ip_addr.is_private,
                ip_addr.is_unspecified,
                ip_addr.is_loopback,
            ]):
                return False
        return True
    except socket.gaierror:
        return False


@on_false(exception_type=ValueError, message="error resolving FQDN.")
def _is_fqdn_resolvable(scheme: str, fqdn: str) -> bool:
    """
    https://docs.python.org/3/library/socket.html
    family | AF_UNSPEC (0) | AF_INET (2)     | AF_INET6 (30)
    type   | <any> (0)     | SOCK_STREAM (1) | SOCK_DGRAM (2)
    proto  | <any> (0)     | IPPROTO_TCP (6) | IPPROTO_UDP (17)
    """
    try:
        return True if socket.getaddrinfo(fqdn, scheme, family=0, type=1, proto=6, flags=socket.AI_CANONNAME) else False
    except socket.gaierror:
        return False
