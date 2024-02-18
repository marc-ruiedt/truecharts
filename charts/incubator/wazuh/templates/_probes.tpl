{{- define "wazuh.probes.dashboard" -}}
probes:
  liveness:
    port: {{ .Values.service.main.ports.main.port }}
    type: {{ .Values.service.main.ports.main.protocol }}
  readiness:
    port: {{ .Values.service.main.ports.main.port }}
    type: {{ .Values.service.main.ports.main.protocol }}
  startup:
    port: {{ .Values.service.main.ports.main.port }}
    type: {{ .Values.service.main.ports.main.protocol }}
{{- end -}}

{{- define "wazuh.probes.indexer" -}}
probes:
  liveness:
    port: {{ .Values.service.indexer.ports.indexer.port }}
    type: {{ .Values.service.indexer.ports.indexer.protocol }}
  readiness:
    port: {{ .Values.service.indexer.ports.indexer.port }}
    type: {{ .Values.service.indexer.ports.indexer.protocol }}
  startup:
    port: {{ .Values.service.indexer.ports.indexer.port }}
    type: {{ .Values.service.indexer.ports.indexer.protocol }}
{{- end -}}

{{- define "wazuh.probes.manager" -}}
probes:
  liveness:
    port: {{ .Values.service.manager.ports.api.port }}
    type: {{ .Values.service.manager.ports.api.protocol }}
  readiness:
    port: {{ .Values.service.manager.ports.api.port }}
    type: {{ .Values.service.manager.ports.api.protocol }}
  startup:
    port: {{ .Values.service.manager.ports.api.port }}
    type: {{ .Values.service.manager.ports.api.protocol }}
{{- end -}}

