{{- define "wazuh.service" -}}

service:

  main:
    enabled: true
    primary: true
    targetSelector: main
    type: LoadBalancer
    ports:
      main:
        primary: true
        enabled: true
        port: 443
        protocol: tcp
        targetPort: 5601
        targetSelector: main
        
  indexer:
    enabled: true
    targetSelector: indexer
    type: ClusterIP
    ports:
      indexer:
        enabled: true
        port: 9200
        protocol: tcp
        targetPort: 9200
        targetSelector: indexer

  manager:
    enabled: true
    targetSelector: manager
    type: LoadBalancer
    ports:
      agent-connect:
        enabled: true
        port: 1514
        protocol: tcp
        targetPort: 1514
        targetSelector: manager
      agent-enroll:
        enabled: true
        port: 1515
        protocol: tcp
        targetPort: 1515
        targetSelector: manager
      syslog-collect:
        enabled: true
        port: 514
        protocol: udp
        targetPort: 514
        targetSelector: manager
      api:
        enabled: true
        port: 55000
        protocol: tcp
        targetPort: 55000
        targetSelector: manager

{{- end -}}