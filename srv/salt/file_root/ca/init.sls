{# CA #}
{% set path = 'x509-ca' %}
{% set output_dir = salt['pillar.get'](path ~ ':output','/tmp') %}

{% set cert_dir = output_dir ~ '/pki/tls/certs' %}
{% set key_dir = output_dir ~ '/pki/tls/private' %}
{% set crl_dir = output_dir ~ '/pki/tls/crl' %}

{% set default_c = salt['pillar.get'](path ~ ':defaults:C','AU') %}
{% set default_st = salt['pillar.get'](path ~ ':defaults:ST','Queensland') %}
{% set default_l = salt['pillar.get'](path ~ ':defaults:L','Brisbane') %}
{% set default_o = salt['pillar.get'](path ~ ':defaults:O','Some Org Ltd') %}
{% set default_ou = salt['pillar.get'](path ~ ':defaults:OU','ICT') %}
{% set default_email = salt['pillar.get'](path ~ ':defaults:Email','unknown@some.org') %}

{{ output_dir }}:
  file.directory:
    - mode: 0755
    - makedirs: True

{{ cert_dir }}:
  file.directory:
    - mode: 0750
    - makedirs: True

{{ key_dir }}:
  file.directory:
    - mode: 0700
    - makedirs: True

{{ crl_dir }}:
  file.directory:
    - mode: 0755
    - makedirs: True

{# Iterate Thru Root Level CAs #}
{% for root_name, root_tree in salt['pillar.get'](path ~ ':root', {}).iteritems() %}
{% set root_path = path ~ ':root:' ~ root_name %}

{{ key_dir }}/{{ root_name }}.key:
  x509.private_key_managed:
    - bits: 4096
    - backup: True
    - require:
      - file: {{ key_dir }}

{{ cert_dir }}/{{ root_name }}.crt:
  x509.certificate_managed:
    - signing_private_key: {{ key_dir }}/{{ root_name }}.key
    - CN: {{ salt['pillar.get'](root_path ~ ':CN', 'ERROR') }}
    - C: {{ salt['pillar.get'](root_path ~ ':C', default_c) }}
    - ST: {{ salt['pillar.get'](root_path ~ ':ST', default_st) }}
    - L: {{ salt['pillar.get'](root_path ~':L', default_l) }}
    - basicConstraints: {{ salt['pillar.get'](root_path ~ ':basicConstraints', 'CA:true') }}
    - keyUsage: {{ salt['pillar.get'](root_path ~ ':keyUsage', 'critical cRLSign, keyCertSign') }}
    - subjectKeyIdentifier: {{ salt['pillar.get'](root_path ~ ':subjectKeyIdentifier', 'hash') }}
    - authorityKeyIdentifier: {{ salt['pillar.get'](root_path ~ ':authorityKeyIdentifier', 'keyid,issuer:always') }}
    - days_valid: {{ salt['pillar.get'](root_path ~ ':days_valid', 365) }}
    - days_remaining: {{ salt['pillar.get'](root_path ~ ':days_remaining', 0) }}
    - backup: {{ salt['pillar.get'](root_path ~ ':backup', True) }}
    - require:
      - file: {{ cert_dir}}
      - x509: {{ key_dir }}/{{ root_name }}.key

{{ crl_dir }}/{{ root_name }}.crl:
  x509.crl_managed:
    - signing_private_key: {{ key_dir }}/{{ root_name }}.key
    - signing_cert: {{ cert_dir }}/{{ root_name }}.crt
    - require:
      - file: {{ crl_dir }}
      - x509: {{ key_dir }}/{{ root_name }}.key
      - x509: {{ cert_dir }}/{{ root_name }}.crt

{# Iterate Thru Intermediary Level CAs #}
{% for int_name, int_tree in salt['pillar.get'](root_path ~ ':sub', {}).iteritems() %}
{% set int_path = root_path ~ ':sub:' ~ int_name %}

{{ key_dir }}/{{ int_name }}.key:
  x509.private_key_managed:
    - bits: 4096
    - backup: True
    - require:
      - file: {{ key_dir }}

{{ cert_dir }}/{{ int_name }}.crt:
  x509.certificate_managed:
    - public_key: {{ key_dir }}/{{ int_name }}.key
    - signing_private_key: {{ key_dir }}/{{ root_name }}.key
    - signing_cert: {{ cert_dir }}/{{ root_name }}.crt
    - CN: {{ salt['pillar.get'](int_path ~ ':CN', 'ERROR') }}
    - C: {{ salt['pillar.get'](int_path ~ ':C', default_c) }}
    - ST: {{ salt['pillar.get'](int_path ~ ':ST', default_st) }}
    - L: {{ salt['pillar.get'](int_path ~':L', default_l) }}
    - basicConstraints: {{ salt['pillar.get'](int_path ~ ':basicConstraints', 'CA:true') }}
    - keyUsage: {{ salt['pillar.get'](int_path ~ ':keyUsage', 'critical cRLSign, keyCertSign') }}
    - subjectKeyIdentifier: {{ salt['pillar.get'](int_path ~ ':subjectKeyIdentifier', 'hash') }}
    - authorityKeyIdentifier: {{ salt['pillar.get'](int_path ~ ':authorityKeyIdentifier', 'keyid,issuer:always') }}
    - days_valid: {{ salt['pillar.get'](int_path ~ ':days_valid', 365) }}
    - days_remaining: {{ salt['pillar.get'](int_path ~ ':days_remaining', 0) }}
    - backup: {{ salt['pillar.get'](int_path ~ ':backup', True) }}
    - require:
      - file: {{ cert_dir}}
      - x509: {{ key_dir }}/{{ int_name }}.key

{{ crl_dir }}/{{ int_name }}.crl:
  x509.crl_managed:
    - signing_private_key: {{ key_dir }}/{{ int_name }}.key
    - signing_cert: {{ cert_dir }}/{{ int_name }}.crt
    - require:
      - file: {{ crl_dir }}
      - x509: {{ key_dir }}/{{ int_name }}.key
      - x509: {{ cert_dir }}/{{ int_name }}.crt

{# Iterate Thru Top Level CAs #}
{% for top_name, top_tree in salt['pillar.get'](int_path ~ ':sub', {}).iteritems() %}
{% set top_path = int_path ~ ':sub:' ~ top_name %}

{{ key_dir }}/{{ top_name }}.key:
  x509.private_key_managed:
    - bits: 4096
    - backup: True
    - require:
      - file: {{ key_dir }}

{{ cert_dir }}/{{ top_name }}.crt:
  x509.certificate_managed:
    - public_key: {{ key_dir }}/{{ top_name }}.key
    - signing_private_key: {{ key_dir }}/{{ int_name }}.key
    - signing_cert: {{ cert_dir }}/{{ int_name }}.crt
    - CN: {{ salt['pillar.get'](top_path ~ ':CN', 'ERROR') }}
    - C: {{ salt['pillar.get'](top_path ~ ':C', default_c) }}
    - ST: {{ salt['pillar.get'](top_path ~ ':ST', default_st) }}
    - L: {{ salt['pillar.get'](top_path ~':L', default_l) }}
    - basicConstraints: {{ salt['pillar.get'](top_path ~ ':basicConstraints', 'CA:true') }}
    - keyUsage: {{ salt['pillar.get'](top_path ~ ':keyUsage', 'critical cRLSign, keyCertSign') }}
    - subjectKeyIdentifier: {{ salt['pillar.get'](top_path ~ ':subjectKeyIdentifier', 'hash') }}
    - authorityKeyIdentifier: {{ salt['pillar.get'](top_path ~ ':authorityKeyIdentifier', 'keyid,issuer:always') }}
    - days_valid: {{ salt['pillar.get'](top_path ~ ':days_valid', 365) }}
    - days_remaining: {{ salt['pillar.get'](top_path ~ ':days_remaining', 0) }}
    - backup: {{ salt['pillar.get'](top_path ~ ':backup', True) }}
    - require:
      - file: {{ cert_dir}}
      - x509: {{ key_dir }}/{{ top_name }}.key

{{ crl_dir }}/{{ top_name }}.crl:
  x509.crl_managed:
    - signing_private_key: {{ key_dir }}/{{ top_name }}.key
    - signing_cert: {{ cert_dir }}/{{ top_name }}.crt
    - require:
      - file: {{ crl_dir }}
      - x509: {{ key_dir }}/{{ top_name }}.key
      - x509: {{ cert_dir }}/{{ top_name }}.crt

{# Create Certificates #}
{% for cert_name, cert_tree in salt['pillar.get'](top_path ~ ':create', {}).iteritems() %}
{% set cert_path = top_path ~ ':create:' ~ cert_name %}

{{ key_dir }}/{{ cert_name }}.key:
  x509.private_key_managed:
    - bits: 4096
    - backup: True
    - require:
      - file: {{ key_dir }}

{{ cert_dir }}/{{ cert_name }}.crt:
  x509.certificate_managed:
    - public_key: {{ key_dir }}/{{ cert_name }}.key
    - signing_private_key: {{ key_dir }}/{{ top_name }}.key
    - signing_cert: {{ cert_dir }}/{{ top_name }}.crt
    - CN: {{ salt['pillar.get'](cert_path ~ ':CN', 'ERROR') }}
    - C: {{ salt['pillar.get'](cert_path ~ ':C', default_c) }}
    - ST: {{ salt['pillar.get'](cert_path ~ ':ST', default_st) }}
    - L: {{ salt['pillar.get'](cert_path ~':L', default_l) }}
    - basicConstraints: {{ salt['pillar.get'](cert_path ~ ':basicConstraints', 'CA:false') }}
    - keyUsage: {{ salt['pillar.get'](cert_path ~ ':keyUsage', 'digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement') }}
    - nsCertType: {{ salt['pillar.get'](cert_path ~ ':nsCertType', 'client, server, email, objsign') }}
    - subjectKeyIdentifier: {{ salt['pillar.get'](cert_path ~ ':subjectKeyIdentifier', 'hash') }}
    - authorityKeyIdentifier: {{ salt['pillar.get'](cert_path ~ ':authorityKeyIdentifier', 'keyid,issuer:always') }}
    - days_valid: {{ salt['pillar.get'](cert_path ~ ':days_valid', 365) }}
    - days_remaining: {{ salt['pillar.get'](cert_path ~ ':days_remaining', 0) }}
    - backup: {{ salt['pillar.get'](cert_path ~ ':backup', True) }}
    - require:
      - file: {{ cert_dir}}
      - x509: {{ key_dir }}/{{ cert_name }}.key

{% endfor %}
{% endfor %}
{% endfor %}
{% endfor %}

{# EOF #}
