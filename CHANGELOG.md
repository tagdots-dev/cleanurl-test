# CHANGELOG

## 1.3.5 (2025-12-17)

### Feat

- add options (allow_redirect, skip_tls) and fix _has_invalid_expired_cert

## 1.3.3 (2025-12-16)

### Feat

- refactor log message, docstring, tld script

## 1.3.0 (2025-12-16)

### Feat

- feature to enable/disable console log, fine-tune get_url_component, fqdn network layer

## 1.2.0 (2025-12-16)

### Feat

- refactor

## 1.1.0 (2025-12-11)

### Feat

- major changes across all modules

### Fix

- add back TLS minimum version at 1.2
- action checkout v6 introduces duplicate header error

## 1.0.1 (2025-12-10)

### Fix

- add ver.py to print version for non-cli/click package
- remove leading space
- fix build version to use low-level command

## 1.0.0 (2025-12-09)

### Feat

- initial commit

### Fix

- add ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
