{{- define "wazuh.persistence" -}}

{{- $certTmpMountPath := "/bad-ownership-cert" -}}
{{- $confTmpMountPath := "/bad-ownership-conf" -}}
{{- $indexerCertMountPath := "/usr/share/wazuh-indexer/certs" -}}

persistence:

## ======= General ======= ##
# ===== Secret ===== #

  root-ca:
    enabled: true
    readOnly: false
    defaultMode: "0600"
    type: secret
    objectName: root-ca
    items:
      - key: tls.crt
        path: root-ca.pem
    targetSelector:
      main:
        init-perms:
          mountPath: {{ $certTmpMountPath }}/general

## ======= Wazuh Dashboard ======= ##
# ===== PVC ===== #

  dashboard-config:
    enabled: true
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      main:
        main:
          mountPath: "/usr/share/wazuh-dashboard/data/wazuh/config"

  dashboard-custom:
    enabled: true
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      main:
        main:
          mountPath: "/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom"

  dashboard-opensearch-conf:
    enabled: true
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      main:
        main:
          mountPath: /wazuh-config
        init-perms:
          mountPath: /wazuh-dashboard-conf

  dashboard-certs:
    enabled: true
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      main:
        init-perms:
          mountPath: /wazuh-dashboard-certs
        main:
          mountPath: /usr/share/wazuh-dashboard/certs

# ===== Secret ===== #

  dashboard-certs-tmp:
    enabled: true
    readOnly: false
    defaultMode: "0600"
    type: secret
    objectName: dashboard-cert
    items:
      - key: tls.key
        path: wazuh-dashboard-key.pem
      - key: tls.crt
        path: wazuh-dashboard.pem
    targetSelector:
      main:
        init-perms:
          mountPath: {{ $certTmpMountPath }}/dashboard
          
  dashboard-opensearch-conf-secret:
    enabled: true
    readOnly: false
    defaultMode: "0600"
    type: configmap
    objectName: dashboard-conf
    items:
      - key: wazuh.yml
        path: wazuh.yml
      - key: opensearch_dashboards.yml
        path: opensearch_dashboards.yml
    targetSelector:
      main:
        init-perms:
          mountPath: {{ $confTmpMountPath }}/dashboard

## ======= Wazuh Indexer ======= ##
# ===== PVC ===== #

  indexer:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    accessModes: ReadWriteOnce
    targetSelector:
      indexer:
        indexer:
          mountPath: "/var/lib/wazuh-indexer"

  indexer-opensearch-conf:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
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
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    targetSelector:
      main:
        init-perms:
          mountPath: /wazuh-indexer-certs
      indexer:
        indexer:
          mountPath: {{ $indexerCertMountPath }}

# ===== Secret ===== #

  indexer-certs-tmp:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    defaultMode: "0600"
    readOnly: false
    type: secret
    objectName: node-cert
    items:
      - key: tls.key
        path: wazuh.indexer.key
      - key: tls.crt
        path: wazuh.indexer.pem
    targetSelector:
      main:
        init-perms:
          mountPath: {{ $certTmpMountPath }}/indexer/node

  admin-certs-tmp:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    readOnly: false
    defaultMode: "0600"
    type: secret
    objectName: admin-cert
    items:
      - key: tls.key
        path: admin-key.pem
      - key: tls.crt
        path: admin.pem
    targetSelector:
      main:
        init-perms:
          mountPath: {{ $certTmpMountPath }}/indexer/admin

  indexer-conf-secret:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    readOnly: false
    defaultMode: "0600"
    type: configmap
    objectName: indexer-conf
    items:
      - key: wazuh.indexer.yml
        path: opensearch.yml
      - key: internal_users.yml
        path: internal_users.yml
    targetSelector:
      main:
        init-perms:
          mountPath: {{ $confTmpMountPath }}/indexer

## ======= Wazuh Manager ======= ##
# ===== PVC ===== #

  manager-certs:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /etc/ssl/
      main: 
        init-perms:
          mountPath: /wazuh-manager-certs

  manager-api-configuration:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/api/configuration

  manager-etc:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/etc
        codeserver:
          mountPath: /var/ossec/etc

  manager-logs:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/logs
        codeserver:
          mountPath: /var/ossec/logs

  manager-queue:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/queue

  manager-var-multigroups:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/var/multigroups

  manager-integrations:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/integrations

  manager-active-response:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/active-response/bin

  manager-agentless:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/agentless

  manager-wodles:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/ossec/wodles

  manager-filebeat-etc:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /etc/filebeat

  manager-filebeat-var:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /var/lib/filebeat

  manager-conf:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    targetSelector:
      manager:
        manager:
          mountPath: /wazuh-config-mount/etc/
      main:
        init-perms:
          mountPath: /wazuh-manager-conf

# ===== Secret ===== #

  manager-certs-tmp:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    type: secret
    objectName: filebeat-cert
    items:
      - key: tls.key
        path: filebeat.key
      - key: tls.crt
        path: filebeat.pem
    targetSelector:
      main:
        init-perms:
          mountPath: {{ $certTmpMountPath }}/manager

  manager-conf-secret:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    readOnly: false
    defaultMode: "0600"
    type: configmap
    objectName: manager-conf
    targetSelector:
      main:
        init-perms:
          mountPath: {{ $confTmpMountPath }}/manager

{{- end -}}