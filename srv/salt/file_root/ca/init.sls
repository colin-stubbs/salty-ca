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
    - makedirs: True

{{ cert_dir }}:
  file.directory:
    - makedirs: True

{{ key_dir }}:
  file.directory:
    - makedirs: True

{{ crl_dir }}:
  file.directory:
    - makedirs: True

{% set optional_attributes = ['GN', 'SN', 'public_key', 'csr', 'extendedKeyUsage', 'issuerAltName', 'subjectAltName', 'crlDistributionPoints', 'issuingDistributionPoint', 'certificatePolicies', 'policyConstraints', 'inhibitAnyPolicy', 'nameConstraints', 'noCheck', 'nsComment', 'nsCertType', 'days_valid', 'version', 'serial_number', 'serial_bits', 'algorithm', 'copypath', 'signing_policy', 'backup'] %}
{% set revoked_attributes = ['certificate', 'serial_number', 'not_after', 'revocation_date', 'reason'] %}

{# Iterate Thru Root Level CAs #}
{% for root_name, root_tree in salt['pillar.get'](path ~ ':root', {}).iteritems() %}
{% set root_path = path ~ ':root:' ~ root_name %}

{% set current_name = root_name %}
{% set current_path = root_path %}

{% set signing_private_key = salt['pillar.get'](current_path ~ ':signing_private_key', '') %}
{% set signing_cert = salt['pillar.get'](current_path ~ ':signing_cert', '') %}
{% if signing_private_key == '' %}

{{ key_dir }}/{{ current_name }}.key:
  x509.private_key_managed:
    - bits: 4096
    - backup: True
    - require:
      - file: {{ key_dir }}

{% endif %}

{{ cert_dir }}/{{ current_name }}.crt:
  x509.certificate_managed:
    - signing_private_key: {{ salt['pillar.get'](current_path ~ ':signing_private_key', key_dir ~ '/' ~ current_name ~ '.key') }}
    {%- if signing_cert != '' %}
    - signing_cert: {{ signing_cert }}
    {%- endif %}
    - public_key: {{ key_dir }}/{{ current_name }}.key
    - CN: {{ salt['pillar.get'](current_path ~ ':CN', 'ERROR') }}
    - C: {{ salt['pillar.get'](current_path ~ ':C', default_c) }}
    - ST: {{ salt['pillar.get'](current_path ~ ':ST', default_st) }}
    - L: {{ salt['pillar.get'](current_path ~':L', default_l) }}
    - Email: {{ salt['pillar.get'](current_path ~':Email', default_email) }}
    - O: {{ salt['pillar.get'](current_path ~ ':O', default_o) }}
    - OU: {{ salt['pillar.get'](current_path ~ ':OU', default_ou) }}
    - basicConstraints: {{ salt['pillar.get'](current_path ~ ':basicConstraints', 'critical CA:true') }}
    - keyUsage: {{ salt['pillar.get'](current_path ~ ':keyUsage', 'critical digitalSignature, cRLSign, keyCertSign') }}
    - subjectKeyIdentifier: {{ salt['pillar.get'](current_path ~ ':subjectKeyIdentifier', 'hash') }}
    - authorityKeyIdentifier: {{ salt['pillar.get'](current_path ~ ':authorityKeyIdentifier', 'keyid,issuer:always') }}
    {%- for attribute in optional_attributes %}
    {%- set value = salt['pillar.get'](current_path ~ ':' ~ attribute, '') %}
    {%- if value != '' %}
    - {{ attribute }}: {{ value }}
    {%- endif %}
    {%- endfor %}
    - require:
      - file: {{ cert_dir}}
      - x509: {{ key_dir }}/{{ current_name }}.key

{% set crl_file = salt['pillar.get'](current_path ~ ':crl_file', crl_dir ~ '/' ~ current_name ~ '.crl') %}
{% set revoked = salt['pillar.get'](current_path ~ ':revoked', {}) %}

{{ crl_file }}:
  x509.crl_managed:
    {%- if signing_private_key == '' %}
    - signing_private_key: {{ key_dir }}/{{ current_name }}.key
    - signing_cert: {{ cert_dir }}/{{ current_name }}.crt
    {%- else %}
    - signing_private_key: {{ signing_private_key }}
    - signing_cert: {{ signing_cert }}
    {%- endif %}
    {%- if revoked != {} %}
    - revoked:
      {%- for revoked_name, revoked_tree in revoked.iteritems() %}
      - {{ revoked_name }}:
        {%- for revoked_attribute in revoked_attributes %}
        {%- set revoked_value = salt['pillar.get'](current_path ~ ':revoked:' ~ revoked_name ~ ':' ~ revoked_attribute, '') %}
        {%- if revoked_value != '' %}
        - {{ revoked_attribute }}: {{ revoked_value }}
        {%- endif %}
        {%- endfor %}
      {%- endfor %}
    {%- endif %}
    - require:
      - file: {{ crl_dir }}
      {%- if signing_private_key == '' %}
      - x509: {{ key_dir }}/{{ current_name }}.key
      - x509: {{ cert_dir }}/{{ current_name }}.crt
      {%- endif %}

{# Iterate Thru Intermediary Level CAs #}
{% for int_name, int_tree in salt['pillar.get'](root_path ~ ':sub', {}).iteritems() %}
{% set int_path = root_path ~ ':sub:' ~ int_name %}

{% set current_name = int_name %}
{% set current_path = int_path %}

{% set signing_private_key = salt['pillar.get'](current_path ~ ':signing_private_key', '') %}
{% set signing_cert = salt['pillar.get'](current_path ~ ':signing_cert', '') %}
{% if signing_private_key == '' %}

{{ key_dir }}/{{ int_name }}.key:
  x509.private_key_managed:
    - bits: 4096
    - backup: True
    - require:
      - file: {{ key_dir }}

{% endif %}

{{ cert_dir }}/{{ current_name }}.crt:
  x509.certificate_managed:
    - signing_private_key: {{ salt['pillar.get'](current_path ~ ':signing_private_key', key_dir ~ '/' ~ root_name ~ '.key') }}
    {%- if signing_cert != '' %}
    - signing_cert: {{ signing_cert }}
    {%- else %}
    - signing_cert: {{ cert_dir }}/{{ root_name }}.crt
    {%- endif %}
    - public_key: {{ key_dir }}/{{ current_name }}.key
    - CN: {{ salt['pillar.get'](current_path ~ ':CN', 'ERROR') }}
    - C: {{ salt['pillar.get'](current_path ~ ':C', default_c) }}
    - ST: {{ salt['pillar.get'](current_path ~ ':ST', default_st) }}
    - L: {{ salt['pillar.get'](current_path ~':L', default_l) }}
    - Email: {{ salt['pillar.get'](current_path ~':Email', default_email) }}
    - O: {{ salt['pillar.get'](current_path ~ ':O', default_o) }}
    - OU: {{ salt['pillar.get'](current_path ~ ':OU', default_ou) }}
    - basicConstraints: {{ salt['pillar.get'](current_path ~ ':basicConstraints', 'critical CA:true') }}
    - keyUsage: {{ salt['pillar.get'](current_path ~ ':keyUsage', 'critical digitalSignature, cRLSign, keyCertSign') }}
    - subjectKeyIdentifier: {{ salt['pillar.get'](current_path ~ ':subjectKeyIdentifier', 'hash') }}
    - authorityKeyIdentifier: {{ salt['pillar.get'](current_path ~ ':authorityKeyIdentifier', 'keyid,issuer:always') }}
    {%- for attribute in optional_attributes %}
    {%- set value = salt['pillar.get'](current_path ~ ':' ~ attribute, '') %}
    {%- if value != '' %}
    - {{ attribute }}: {{ value }}
    {%- endif %}
    {%- endfor %}
    - require:
      - file: {{ cert_dir}}
      - x509: {{ key_dir }}/{{ current_name }}.key

{% set crl_file = salt['pillar.get'](current_path ~ ':crl_file', crl_dir ~ '/' ~ current_name ~ '.crl') %}
{% set revoked = salt['pillar.get'](current_path ~ ':revoked', {}) %}

{{ crl_file }}:
  x509.crl_managed:
    {%- if signing_private_key == '' %}
    - signing_private_key: {{ key_dir }}/{{ current_name }}.key
    - signing_cert: {{ cert_dir }}/{{ current_name }}.crt
    {%- else %}
    - signing_private_key: {{ signing_private_key }}
    - signing_cert: {{ signing_cert }}
    {%- endif %}
    {%- if revoked != {} %}
    - revoked:
      {%- for revoked_name, revoked_tree in revoked.iteritems() %}
      - {{ revoked_name }}:
        {%- for revoked_attribute in revoked_attributes %}
        {%- set revoked_value = salt['pillar.get'](current_path ~ ':revoked:' ~ revoked_name ~ ':' ~ revoked_attribute, '') %}
        {%- if revoked_value != '' %}
        - {{ revoked_attribute }}: {{ revoked_value }}
        {%- endif %}
        {%- endfor %}
      {%- endfor %}
    {%- endif %}
    - require:
      - file: {{ crl_dir }}
      {%- if signing_private_key == '' %}
      - x509: {{ key_dir }}/{{ current_name }}.key
      - x509: {{ cert_dir }}/{{ current_name }}.crt
      {%- endif %}

{# Iterate Thru Top Level CAs #}
{% for top_name, top_tree in salt['pillar.get'](int_path ~ ':sub', {}).iteritems() %}
{% set top_path = int_path ~ ':sub:' ~ top_name %}

{% set current_name = top_name %}
{% set current_path = top_path %}

{% set signing_private_key = salt['pillar.get'](current_path ~ ':signing_private_key', '') %}
{% set signing_cert = salt['pillar.get'](current_path ~ ':signing_cert', '') %}
{% if signing_private_key == '' %}

{{ key_dir }}/{{ top_name }}.key:
  x509.private_key_managed:
    - bits: 4096
    - backup: True
    - require:
      - file: {{ key_dir }}

{% endif %}

{{ cert_dir }}/{{ current_name }}.crt:
  x509.certificate_managed:
    - signing_private_key: {{ salt['pillar.get'](current_path ~ ':signing_private_key', key_dir ~ '/' ~ int_name ~ '.key') }}
    {%- if signing_cert != '' %}
    - signing_cert: {{ signing_cert }}
    {%- else %}
    - signing_cert: {{ cert_dir }}/{{ int_name }}.crt
    {%- endif %}
    - public_key: {{ key_dir }}/{{ current_name }}.key
    - CN: {{ salt['pillar.get'](current_path ~ ':CN', 'ERROR') }}
    - C: {{ salt['pillar.get'](current_path ~ ':C', default_c) }}
    - ST: {{ salt['pillar.get'](current_path ~ ':ST', default_st) }}
    - L: {{ salt['pillar.get'](current_path ~':L', default_l) }}
    - Email: {{ salt['pillar.get'](current_path ~':Email', default_email) }}
    - O: {{ salt['pillar.get'](current_path ~ ':O', default_o) }}
    - OU: {{ salt['pillar.get'](current_path ~ ':OU', default_ou) }}
    - basicConstraints: {{ salt['pillar.get'](current_path ~ ':basicConstraints', 'critical CA:true, pathlen:0') }}
    - keyUsage: {{ salt['pillar.get'](current_path ~ ':keyUsage', 'critical digitalSignature, cRLSign, keyCertSign') }}
    - subjectKeyIdentifier: {{ salt['pillar.get'](current_path ~ ':subjectKeyIdentifier', 'hash') }}
    - authorityKeyIdentifier: {{ salt['pillar.get'](current_path ~ ':authorityKeyIdentifier', 'keyid,issuer:always') }}
    {%- for attribute in optional_attributes %}
    {%- set value = salt['pillar.get'](current_path ~ ':' ~ attribute, '') %}
    {%- if value != '' %}
    - {{ attribute }}: {{ value }}
    {%- endif %}
    {%- endfor %}
    - require:
      - file: {{ cert_dir}}
      - x509: {{ key_dir }}/{{ current_name }}.key

{% set crl_file = salt['pillar.get'](current_path ~ ':crl_file', crl_dir ~ '/' ~ current_name ~ '.crl') %}
{% set revoked = salt['pillar.get'](current_path ~ ':revoked', {}) %}

{{ crl_file }}:
  x509.crl_managed:
    {%- if signing_private_key == '' %}
    - signing_private_key: {{ key_dir }}/{{ current_name }}.key
    - signing_cert: {{ cert_dir }}/{{ current_name }}.crt
    {%- else %}
    - signing_private_key: {{ signing_private_key }}
    - signing_cert: {{ signing_cert }}
    {%- endif %}
    {%- if revoked != {} %}
    - revoked:
      {%- for revoked_name, revoked_tree in revoked.iteritems() %}
      - {{ revoked_name }}:
        {%- for revoked_attribute in revoked_attributes %}
        {%- set revoked_value = salt['pillar.get'](current_path ~ ':revoked:' ~ revoked_name ~ ':' ~ revoked_attribute, '') %}
        {%- if revoked_value != '' %}
        - {{ revoked_attribute }}: {{ revoked_value }}
        {%- endif %}
        {%- endfor %}
      {%- endfor %}
    {%- endif %}
    - require:
      - file: {{ crl_dir }}
      {%- if signing_private_key == '' %}
      - x509: {{ key_dir }}/{{ current_name }}.key
      - x509: {{ cert_dir }}/{{ current_name }}.crt
      {%- endif %}

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
    - Email: {{ salt['pillar.get'](cert_path ~':Email', default_email) }}
    - O: {{ salt['pillar.get'](cert_path ~ ':O', default_o) }}
    - OU: {{ salt['pillar.get'](cert_path ~ ':OU', default_ou) }}
    - basicConstraints: {{ salt['pillar.get'](cert_path ~ ':basicConstraints', 'CA:false') }}
    - keyUsage: {{ salt['pillar.get'](cert_path ~ ':keyUsage', 'digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement') }}
    - subjectKeyIdentifier: {{ salt['pillar.get'](cert_path ~ ':subjectKeyIdentifier', 'hash') }}
    - authorityKeyIdentifier: {{ salt['pillar.get'](cert_path ~ ':authorityKeyIdentifier', 'keyid,issuer:always') }}
    - days_valid: {{ salt['pillar.get'](cert_path ~ ':days_valid', 365) }}
    {%- for attribute in optional_attributes %}
    {%- set value = salt['pillar.get'](cert_path ~ ':' ~ attribute, '') %}
    {%- if value != '' %}
    - {{ attribute }}: {{ value }}
    {%- endif %}
    {%- endfor %}
    - require:
      - file: {{ cert_dir}}
      - x509: {{ key_dir }}/{{ cert_name }}.key

{% endfor %}
{% endfor %}
{% endfor %}
{% endfor %}

{# EOF #}
