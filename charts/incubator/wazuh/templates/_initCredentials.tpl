{{- define "wazuh.init.credentials" -}}

enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
primary: true
type: install
imageSelector: indexerImage
command: /bin/sh
args:
  - -c
  - |
    ls -la /
    ls -la /wazuh-config

    chmod +x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh 
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk

    cat <<EOF >> /wazuh-config/internal_users.yml

    ---
    # This is the internal user database
    # The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

    _meta:
      type: "internalusers"
      config_version: 2

    # Define your internal users here

    ## Demo users 

    {{ .Values.wazuh.outposts.indexer.username }}:
        hash: "$(echo $(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "{{ .Values.wazuh.outposts.indexer.password }}") | awk '{print $NF}')"
        reserved: true
        backend_roles:
        - "admin"
        description: "Default admin user"

    {{ .Values.wazuh.credentials.username }}:
        hash: "$(echo $(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "{{ .Values.wazuh.credentials.password }}") | awk '{print $NF}')"
        reserved: true
        description: "Default dashboard user"
    EOF

    cat /wazuh-config/internal_users.yml

{{- end -}}