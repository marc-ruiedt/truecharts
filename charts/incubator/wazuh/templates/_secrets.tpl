{{/* Define the secrets */}}
{{- define "wazuh.secrets" -}}

{{- $fullName := (include "tc.v1.common.lib.chart.names.fullname" $) -}}
{{- $namespace := (include "tc.v1.common.lib.metadata.namespace" (dict "rootCtx" $ "objectData" . "caller" "Configmap")) -}}
{{- $indexerUrl := printf "%s-indexer.%s.svc.cluster.local" $fullName $namespace -}}

{{- $dashboardCredentialsSecret := printf "%s-dashboard-credentials" (include "tc.v1.common.lib.chart.names.fullname" .) -}}
{{- $indexerCredentialsSecret := printf "%s-indexer-credentials" (include "tc.v1.common.lib.chart.names.fullname" .) -}}
{{- $managerCredentialsSecret := printf "%s-manager-credentials" (include "tc.v1.common.lib.chart.names.fullname" .) -}}

{{- $dashboardUsername := .Values.wazuh.credentials.username -}}
{{- $dashboardPassword := .Values.wazuh.credentials.password -}}
{{- with lookup "v1" "Secret" .Release.Namespace $dashboardCredentialsSecret -}}
  {{- $dashboardUsername = index .data "username" | b64dec -}}
  {{- $dashboardPassword = index .data "password" | b64dec -}}
{{- end }}

{{- $indexerUsername := .Values.wazuh.outposts.indexer.username -}}
{{- $indexerPassword := .Values.wazuh.outposts.indexer.password -}}
{{- with lookup "v1" "Secret" .Release.Namespace $indexerCredentialsSecret -}}
  {{- $indexerUsername = index .data "username" | b64dec -}}
  {{- $indexerPassword = index .data "password" | b64dec -}}
{{- end }}

{{- $managerUsername := .Values.wazuh.outposts.manager.username -}}
{{- $managerPassword := .Values.wazuh.outposts.manager.password -}}
{{- with lookup "v1" "Secret" .Release.Namespace $managerCredentialsSecret -}}
  {{- $managerUsername = index .data "username" | b64dec -}}
  {{- $managerPassword = index .data "password" | b64dec -}}
{{- end }}

{{/* Generate Root CA */}}
{{- $rootCA := genCA "root-ca" 3650 -}}

{{/* Generate and Store Admin Certificate */}}
{{- $adminCert := genSignedCert "admin" nil nil 3650 $rootCA -}}

{{/* Generate and Store Node Certificate */}}
{{- $nodeCert := genSignedCert $indexerUrl nil nil 3650 $rootCA -}}

{{/* Generate and Store Dashboard Certificate */}}
{{- $dashboardCert := genSignedCert "dashboard" nil nil 3650 $rootCA -}}

{{/* Generate and Store Filebeat Certificate */}}
{{- $filebeatCert := genSignedCert "filebeat" nil nil 3650 $rootCA -}}

secret:
  dashboard-credentials:
    enabled: true
    data:
      username: {{ $dashboardUsername | quote }}
      password: {{ $dashboardPassword | quote }}

  indexer-credentials:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    data:
      username: {{ $indexerUsername | quote }}
      password: {{ $indexerPassword | quote }}

  manager-credentials:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    data:
      username: {{ $managerUsername | quote }}
      password: {{ $managerPassword | quote }}

  root-ca:
    enabled: true
    type: kubernetes.io/tls
    data:
      tls.key: {{ $rootCA.Key | quote }}
      tls.crt: {{ $rootCA.Cert | quote }}

  admin-cert:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    type: kubernetes.io/tls
    data:
      tls.key: {{ $adminCert.Key | quote }}
      tls.crt: {{ $adminCert.Cert | quote }}

  node-cert:
    enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
    type: kubernetes.io/tls
    data:
      tls.key: {{ $nodeCert.Key | quote }}
      tls.crt: {{ $nodeCert.Cert | quote }}

  dashboard-cert:
    enabled: true
    type: kubernetes.io/tls
    data:
      tls.key: {{ $dashboardCert.Key | quote }}
      tls.crt: {{ $dashboardCert.Cert | quote }}

  filebeat-cert:
    enabled: {{ .Values.wazuh.outposts.manager.enabled }}
    type: kubernetes.io/tls
    data:
      tls.key: {{ $filebeatCert.Key | quote }}
      tls.crt: {{ $filebeatCert.Cert | quote }}

{{- end -}}