{{/* Wordpress environment variables */}}
{{- define "wazuh.env" -}}

{{- $fullName := (include "tc.v1.common.lib.chart.names.fullname" $) -}}
{{- $namespace := (include "tc.v1.common.lib.metadata.namespace" (dict "rootCtx" $ "objectData" . "caller" "Configmap")) -}}
{{- $fqdn := (include "tc.v1.common.lib.chart.names.fqdn" $) -}}
{{- $dashboardUrl := printf "%s.svc.cluster.local" $fqdn -}}
{{- $managerUrl := printf "%s-manager.%s.svc.cluster.local" $fullName $namespace -}}
{{- $indexerUrl := printf "%s-indexer.%s.svc.cluster.local" $fullName $namespace -}}
{{- $indexerPort := printf "%v" .Values.service.indexer.ports.indexer.port -}}
{{- $dashboardPort := printf "%v" .Values.service.main.ports.main.port -}}

configmap:
  dashboard-env:
    enabled: true
    data:
      WAZUH_API_URL: {{ $managerUrl | quote }}
  indexer-env:
    enabled: true
    data:
      OPENSEARCH_JAVA_OPTS: "-Xms1024m -Xmx1024m"
  manager-env:
    enabled: true
    data:
      INDEXER_URL: {{ printf "%s:%v" $indexerUrl $indexerPort | quote }}
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
    enabled: true
    data:
      INDEXER_USERNAME: {{ .Values.wazuh.outposts.indexer.username | quote }}
      INDEXER_PASSWORD: {{ .Values.wazuh.outposts.indexer.password | quote }}
      API_USERNAME: {{ .Values.wazuh.outposts.manager.username | quote }}
      API_PASSWORD: {{ .Values.wazuh.outposts.manager.password | quote }}
{{- end }}