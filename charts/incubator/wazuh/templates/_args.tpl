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

    chmod +x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh 
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk

    cat <<EOF > /wazuh-config/internal_users.yml

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
        backend_roles:
        - "admin"
        description: "Default admin user"
    EOF

    ln -sf /wazuh-config/opensearch.yml /usr/share/wazuh-indexer/opensearch.yml
    ln -sf /wazuh-config/internal_users.yml /usr/share/wazuh-indexer/opensearch-security/internal_users.yml

    /entrypoint.sh &

    # Function to check if port 9200 is open
    check_port() {
        (echo >/dev/tcp/localhost/9200) >/dev/null 2>&1 && return 0 || return 1
    }

    # Wait for port 9200 to become available
    counter=0
    while [ $counter -lt 300 ]; do
        sleep 1
        counter=$((counter+1))
        if check_port; then
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

            # Bring the output of entrypoint.sh to the foreground
            fg 1
            break
        fi
    done

    if [ $counter -eq 300 ]; then
        echo "Timeout: Port 9200 not open after 5 minutes."
        echo "The change of login/password cannot take effect."
    fi
{{- end -}}