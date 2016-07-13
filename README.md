# salty-ca
Generates a multi-layer Certificate Authority hierarchy and certificates using Salt Stack.
# Usage
Edit the Salt Stack minion config at %{REPOSITORY}%/etc/minion, change the folder locations as appropriate

Edit the pillar file at %{REPOSITORY}%/srv/salt/pillar_root/ca/init.sls

1. Change the output_dir as desired
2. Change the defaults as desired
3. Modify root, intermediary and top level CA's as appropriate
4. Modify certificate examples as appropriate and define additional certificates as desired

Reference doco:

https://docs.saltstack.com/en/latest/ref/modules/all/salt.modules.x509.html

run %{REPOSITORY}%/run.sh

Find output in the configured output_dir folder.
