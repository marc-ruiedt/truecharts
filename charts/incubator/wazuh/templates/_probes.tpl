{{- define "wazuh.probes.dashboard" -}}
probes:
  liveness:
    port: {{ .Values.service.main.ports.main.port }}
    type: http
    path: "/"
  readiness:
    port: {{ .Values.service.main.ports.main.port }}
    type: http
    path: "/"
  startup:
    port: {{ .Values.service.main.ports.main.port }}
    type: http
    path: "/"
{{- end -}}

{{- define "wazuh.probes.indexer" -}}
probes:
  liveness:
    port: {{ .Values.service.indexer.ports.indexer.port }}
    type: tcp
  readiness:
    port: {{ .Values.service.indexer.ports.indexer.port }}
    type: tcp
  startup:
    port: {{ .Values.service.indexer.ports.indexer.port }}
    type: tcp
{{- end -}}

{{- define "wazuh.probes.manager" -}}
probes:
  liveness:
    port: {{ .Values.service.manager.ports.api.port }}
    type: tcp
  readiness:
    port: {{ .Values.service.manager.ports.api.port }}
    type: tcp
  startup:
    port: {{ .Values.service.manager.ports.api.port }}
    type: tcp
{{- end -}}

