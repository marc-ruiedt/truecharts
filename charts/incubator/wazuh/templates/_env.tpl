{{/* Wordpress environment variables */}}
{{- define "wazuh.env" -}}

{{- $fullName := (include "tc.v1.common.lib.chart.names.fullname" $) -}}
{{- $namespace := (include "tc.v1.common.lib.metadata.namespace" (dict "rootCtx" $ "objectData" . "caller" "Configmap")) -}}
{{- $managerUrl := printf "https://%s-manager.%s.svc.cluster.local" $fullName $namespace -}}
{{- $indexerNodeName := printf "%s-indexer" $fullName -}}
{{- $indexerPort := printf "%v" .Values.service.indexer.ports.indexer.port -}}
{{- $indexerUrl := printf "https://%s.%s.svc.cluster.local:%v" $indexerNodeName $namespace $indexerPort -}}

configmap:
  dashboard-env:
    enabled: true
    data:
      INDEXER_URL: {{ $indexerUrl | quote }}
      SERVER_SSL_ENABLED: "true"
      SERVER_SSL_CERTIFICATE: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
      SERVER_SSL_KEY: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
      WAZUH_API_URL: {{ $managerUrl | quote }}
  indexer-env:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    data:
      OPENSEARCH_JAVA_OPTS: "-Xms1g -Xmx1g -Dlog4j2.formatMsgNoLookups=true"
      CLUSTER_NAME: {{ $fullName | quote }}
      NETWORK_HOST: "0.0.0.0"
      NODE_NAME: {{ $indexerNodeName }}
      DISCOVERY_SERVICE: "wazuh-indexer"
      KUBERNETES_NAMESPACE: {{ $namespace | quote }}
      DISABLE_INSTALL_DEMO_CONFIG: "true"
  manager-env:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    data:
      INDEXER_URL: {{ $indexerUrl | quote }}
      FILEBEAT_SSL_VERIFICATION_MODE: "full"
      SSL_CERTIFICATE_AUTHORITIES: "/etc/ssl/root-ca.pem"
      SSL_CERTIFICATE: "/etc/ssl/filebeat.pem"
      SSL_KEY: "/etc/ssl/filebeat.key"

{{- $secretName := printf "%s-env-secret" (include "tc.v1.common.lib.chart.names.fullname" .) }}
secret:
  dashboard-env:
    enabled: true
    data:
      INDEXER_USERNAME: {{ .Values.wazuh.outposts.indexer.username | quote }}
      INDEXER_PASSWORD: {{ .Values.wazuh.outposts.indexer.password | quote }}
      DASHBOARD_USERNAME: {{ .Values.wazuh.credentials.username | quote }}
      DASHBOARD_PASSWORD: {{ .Values.wazuh.credentials.password | quote }}
      API_USERNAME: {{ .Values.wazuh.outposts.manager.username | quote }}
      API_PASSWORD: {{ .Values.wazuh.outposts.manager.password | quote }}
  manager-env:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    data:
      INDEXER_USERNAME: {{ .Values.wazuh.outposts.indexer.username | quote }}
      INDEXER_PASSWORD: {{ .Values.wazuh.outposts.indexer.password | quote }}
      API_USERNAME: {{ .Values.wazuh.outposts.manager.username | quote }}
      API_PASSWORD: {{ .Values.wazuh.outposts.manager.password | quote }}
{{- end }}