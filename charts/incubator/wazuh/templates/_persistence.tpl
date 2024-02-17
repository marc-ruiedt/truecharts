{{- define "wazuh.persistence" -}}
persistence:

## ======= Debug ======= ##
# ===== PVC ===== #

  # config:
  #   enabled: true
  #   mountPath: /config
  #   targetSelector:
  #     manager:
  #       codeserver:
  #         mountPath: "/var/lib/wazuh-indexer"

## ======= General ======= ##
# ===== Secret ===== #

  root-ca:
    enabled: true
    type: secret
    objectName: root-ca
    readOnly: false
    items:
      - key: tls.crt
        path: root-ca.pem
    targetSelector:
      main:
        init-perms:
          mountPath: /bad-ownership-cert/general

## ======= Wazuh Indexer ======= ##
# ===== PVC ===== #

  indexer:
    enabled: true
    readOnly: false
    # defaultMode: "0600"
    targetSelector:
      indexer:
        indexer:
          mountPath: "/var/lib/wazuh-indexer"

  indexer-opensearch-conf:
    enabled: true
    readOnly: false
    targetSelector:
      main:
        init-perms:
          mountPath: /wazuh-indexer-conf
      indexer:
        indexer:
          mountPath: /wazuh-config
        init-credentials:
          mountPath: /wazuh-config

  indexer-certs:
    enabled: true
    readOnly: false
    targetSelector:
      main:
        init-perms:
          mountPath: /wazuh-indexer-certs
      indexer:
        indexer:
          mountPath: /usr/share/wazuh-indexer/certs

# ===== Secret ===== #

  indexer-certs-tmp:
    enabled: true
    type: secret
    objectName: node-cert
    readOnly: false
    items:
      - key: tls.key
        path: wazuh.indexer.key
      - key: tls.crt
        path: wazuh.indexer.pem
    targetSelector:
      main:
        init-perms:
          mountPath: /bad-ownership-cert/indexer/node

  admin-certs-tmp:
    enabled: true
    type: secret
    objectName: admin-cert
    readOnly: false
    items:
      - key: tls.key
        path: admin-key.pem
      - key: tls.crt
        path: admin.pem
    targetSelector:
      main:
        init-perms:
          mountPath: /bad-ownership-cert/indexer/admin

  indexer-conf-secret:
    enabled: true
    type: configmap
    objectName: indexer-conf
    readOnly: false
    items:
      - key: wazuh.indexer.yml
        path: opensearch.yml
      - key: internal_users.yml
        path: internal_users.yml
    targetSelector:
      main:
        init-perms:
          mountPath: /bad-ownership-conf/indexer

## ======= Wazuh Dashboard ======= ##
# ===== PVC ===== #

  dashboard-config:
    enabled: true
    readOnly: false
    # defaultMode: "0600"
    targetSelector:
      main:
        main:
          mountPath: "/usr/share/wazuh-dashboard/data/wazuh/config"

  dashboard-custom:
    enabled: true
    readOnly: false
    # defaultMode: "0600"
    targetSelector:
      main:
        main:
          mountPath: "/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom"

  dashboard-opensearch-conf:
    enabled: true
    readOnly: false
    targetSelector:
      main:
        main:
          mountPath: /wazuh-config
        init-perms:
          mountPath: /wazuh-dashboard-conf

  dashboard-certs:
    enabled: true
    readOnly: false
    targetSelector:
      main:
        init-perms:
          mountPath: /wazuh-dashboard-certs
        main:
          mountPath: /usr/share/wazuh-dashboard/certs

# ===== Secret ===== #

  dashboard-certs-tmp:
    enabled: true
    type: secret
    objectName: dashboard-cert
    readOnly: false
    items:
      - key: tls.key
        path: wazuh-dashboard-key.pem
      - key: tls.crt
        path: wazuh-dashboard.pem
    targetSelector:
      main:
        init-perms:
          mountPath: /bad-ownership-cert/dashboard
          
  dashboard-opensearch-conf-secret:
    enabled: true
    type: configmap
    objectName: dashboard-conf
    readOnly: false
    items:
      - key: wazuh.yml
        path: wazuh.yml
      - key: opensearch_dashboards.yml
        path: opensearch_dashboards.yml
    targetSelector:
      main:
        init-perms:
          mountPath: /bad-ownership-conf/dashboard

## ======= Wazuh Manager ======= ##
# ===== PVC ===== #

  manager-certs:
    enabled: true
    readOnly: false
    targetSelector:
      manager:
        manager:
          mountPath: /etc/ssl/
      main: 
        init-perms:
          mountPath: /wazuh-manager-certs

  manager-api-configuration:
    enabled: true
    readOnly: false
    # defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/api/configuration

  manager-etc:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/etc
        codeserver:
          mountPath: /var/ossec/etc

  manager-logs:
    enabled: true
    readOnly: false
    # # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/logs
        codeserver:
          mountPath: /var/ossec/logs

  manager-queue:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/queue

  manager-var-multigroups:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/var/multigroups

  manager-integrations:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/integrations

  manager-active-response:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/active-response/bin

  manager-agentless:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/agentless

  manager-wodles:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/wodles

  manager-filebeat-etc:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /etc/filebeat

  manager-filebeat-var:
    enabled: true
    readOnly: false
    # defaultMode: "0400"
    targetSelector:
      manager:
        manager:
          mountPath: /var/lib/filebeat

  manager-conf:
    enabled: true
    readOnly: false
    targetSelector:
      manager:
        manager:
          mountPath: /wazuh-config-mount/etc/
      main:
        init-perms:
          mountPath: /wazuh-manager-conf

# ===== Secret ===== #

  manager-certs-tmp:
    enabled: true
    type: secret
    objectName: filebeat-cert
    readOnly: false
    items:
      - key: tls.key
        path: filebeat.key
      - key: tls.crt
        path: filebeat.pem
    targetSelector:
      main:
        init-perms:
          mountPath: /bad-ownership-cert/manager

  manager-conf-secret:
    enabled: true
    type: configmap
    objectName: manager-conf
    readOnly: false
    targetSelector:
      main:
        init-perms:
          mountPath: /bad-ownership-conf/manager
{{- end -}}