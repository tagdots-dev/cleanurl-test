# ⭐ method: _evaluate_url_

### ✅ Purpose: evaluate URL from syntax to network and transport layers.

### Description

Beside syntax checking, we take URL evaluation up another level to the network and transport layers in order to _**fend off unwanted entries into your API application**_.  For instance, _**evaluate_url**_ returns _**False**_.

```
- insecure practice to embed `userinfo` into the URL (after protocol scheme).
- fqdn resolved to non-public routable IP address (subject to SSRF risk).
- selected control characters found (subject to log ingestion risk).
- use TLS protocol lower than TLSv1.3.
- use hasing algorithm lower than SHA2.
- use invalid HTTPS certificate.
...etc
```

<br>

By default, _**evaluate_url**_ returns _**True**_ when the URL fulfills all of the following
```
1. meet RFC requirements in URL syntax except that
    - userinfo is not supported in authority
    - IPv4/6  are not supported in authority
2. use https protocol scheme.
3. use hostname resolvable to public routable IP address.
4. use valid and secure certificate that employs the latest protocol, strong cipher, & hashing algorithm.
```

<br>

 **🔧 Available options to support YOUR scenarios**
| Parameters           | Description                            | Default |
|----------------------|----------------------------------------|---------|
| `allow_http`         | `allow http protocol in scheme`        | `False` |
| `allow_localhost`    | `allow localhost as FQDN`              | `False` |
| `allow_loopback_ip*` | `allow FQDN resolved to loopback IP`   | `False` |
| `allow_private_ip*`  | `allow FQDN resolved to private IP`    | `False` |
| `allow_redirect*`    | `allow redirect during TLS validation` | `True`  |
| `allow_tlsv12`       | `allow TLSv1.2 encryption protocol`    | `False` |
| `skip_tls`           | `skip TLS validation`                  | `False` |
| `enable_log`         | `enable console log`                   | `False` |

<br>

**⚠️ Notes on available options**<br>
* _allow_loopback_ip_
    - 127.0.0.0/8 (RFC 3330)
    - 0:0:0:0:0:0:0:1 or ::1 (RFC 2373)

* _allow_private_ip_
    - 127.0.0./8 (RFC 3330)
    - 10/8, 172.16/12, 192.168/16 (RFC 1918)
    - 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737)
    - 198.18.0.0/15 (RFC 6815)
    - fe80::/10, fe80::/64 (RFC 4291)

* _allow_redirect_
    - follow redirect may be a grey area and we take the stance to enable this by default because it is generally impractical to avoid website redirects on the Internet.

<br>

### 💥 Running in Python interactive runtime environment

### Import client library
```
>>> from pkg_19544 import evaluate_url
```

### Example 1:  evaluate URL with _https_ scheme
```
>>> user_url = 'https://google.com'

>>> evaluate_url(user_url)
True
```

### Example 2: evaluate URL with _https_ scheme AND _invalid host_
```
>>> user_url = 'https://invalid.host.google.com'

>>> evaluate_url(user_url)
False

>>> evaluate_url(user_url, enable_log=True)
ERROR: unable to resolve FQDN (evaluate.py:143)
False
```

### Example 3: evaluate URL with _http_ scheme
```
>>> user_url = 'http://google.com'

>>> evaluate_url(user_url)
False

>>> evaluate_url(user_url, enable_log=True)
ERROR: invalid protocol scheme prefix (clean_url.py:49)
False

>>> evaluate_url(user_url, allow_http=True)
True
```

### Example 4: evaluate URL with _http_ scheme and _localhost_
```
>>> user_url = 'http://localhost'

>>> evaluate_url(user_url)
False

>>> evaluate_url(user_url, enable_log=True)
ERROR: invalid protocol scheme prefix (clean_url.py:49)
False

>>> evaluate_url(user_url, allow_http=True, enable_log=True)
ERROR: invalid FQDN - check chars usage, max length of label(63)/ fqdn(255) (clean_url.py:52)
False

>>> evaluate_url(user_url, allow_http=True, allow_localhost=True, enable_log=True)
ERROR: invalid https certificate or connections (clean_url.py:56)
False

>>> evaluate_url(user_url, allow_http=True, allow_localhost=True, skip_tls=True)
True
```

### Example 5: evaluate URL with _https_ scheme and _private-network-host_

**_private_network-host_**<br>
hello-host.yourdomain.com >>
hello-host.us-east-1.my-internal-aws.com >>
ip-10-0-0-123.ec2.internal >>
10.0.0.23

```
>>> user_url = 'https://hello-host.your-doman.com/path1/index.html'

>>> evaluate_url(user_url)
False

>>> evaluate_url(user_url, enable_log=True)
ERROR: FQDN ip address not public routable or disallowed (evaluate.py:144)
False

>>> evaluate_url(user_url, allow_private_ip=True)
True
```
