{{- define "wazuh.dashboard.args" -}}
args:
  - -c
  - |
    id
    ls -la /wazuh-config
    ln -sf /wazuh-config/opensearch_dashboards.yml /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
    ln -sf /wazuh-config/wazuh.yml /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    ls -la /
    ls -la /usr/share/wazuh-dashboard/data/wazuh/config
    ls -la /usr/share/wazuh-dashboard/config
    cat /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
    cat /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    /entrypoint.sh
{{- end -}}

{{- define "wazuh.indexer.args" -}}
args:
  - -c
  - |
    id

    ln -sf /wazuh-config/opensearch.yml /usr/share/wazuh-indexer/opensearch.yml
    ln -sf /wazuh-config/internal_users.yml /usr/share/wazuh-indexer/opensearch-security/internal_users.yml

    /entrypoint.sh

    # Wait for 2 minutes
    sleep 30

    export INSTALLATION_DIR=/usr/share/wazuh-indexer
    CACERT=$INSTALLATION_DIR/certs/root-ca.pem
    KEY=$INSTALLATION_DIR/certs/admin.key
    CERT=$INSTALLATION_DIR/certs/admin.pem
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk

    chmod +x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
        -f /usr/share/wazuh-indexer/opensearch-security/internal_users.yml \
        -t internalusers \
        -icl \
        -nhnv \
        -cacert $CACERT \
        -cert $CERT \
        -key $KEY \
        -p 9200

{{- end -}}