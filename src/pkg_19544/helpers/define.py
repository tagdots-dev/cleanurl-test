from urllib.request import urlopen

from ..configs.constants import TIMEOUT_DEFAULT
from ..helpers.sanitize import _remove_control_characters
from ..utils.err import raise_on_false
from ..utils.url import get_url_components


class ValueError(ValueError):
    pass


@raise_on_false(exception_type=ValueError, message='failed to open URL')
def _define_url(
        user_url: str,
        url_type: str = '',
        trailing_path: str = '',
        enable_log: bool = False) -> str | bool:
    """
    return URL for different usages
    """
    if url_type == 'origin':
        return _sanitized_url(user_url=user_url)
    elif url_type == 'redirect':
        try:
            with urlopen(_sanitized_url(user_url=user_url), timeout=TIMEOUT_DEFAULT) as response:
                response_url = response.url
                trailing_path = '/' + trailing_path if trailing_path and not trailing_path.startswith('/') else trailing_path
                return _sanitized_url(response_url) + trailing_path

        except Exception:
            return False
    else:  # pragma: no cover
        return False


def _sanitized_url(user_url: str) -> str:
    sanitized_url = _remove_control_characters(user_url)
    scheme, _, _, fqdn, port, _ = get_url_components(sanitized_url)
    port = '' if port and port in ['80', '443'] else ':' + port if port else ''

    return scheme + "://" + fqdn + port
