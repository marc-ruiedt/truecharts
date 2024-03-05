{{- define "wazuh.init.waitindexer" -}}
{{- $fullName := (include "tc.v1.common.lib.chart.names.fullname" $) -}}
{{- $namespace := (include "tc.v1.common.lib.metadata.namespace" (dict "rootCtx" $ "objectData" . "caller" "Configmap")) -}}
{{- $indexerPort := printf "%v" .Values.service.indexer.ports.indexer.port -}}
{{- $indexerUrl := printf "https://%s-indexer.%s.svc.cluster.local:%v" $fullName $namespace $indexerPort -}}
enabled: {{ .Values.wazuh.outposts.indexer.enabled }}
primary: true
type: init
imageSelector: alpineImage
securityContext:
command: /bin/sh
args:
  - -c
  - |
    echo "Waiting Indexer [{{ $indexerUrl }}] to be ready..."

    # Function to check if port 9200 is open
    check_port() {
        wget --spider --no-check-certificate -S wazuh-indexer.ix-wazuh.svc.cluster.local:9200
    }

    # Wait for port 9200 to become available
    counter=0
    while [ $counter -lt 600 ]; do
        sleep 1
        counter=$((counter+1))
        
        if check_port; then
            echo true
        else 
            echo false 
        fi
    done

    if [ $counter -eq 600 ]; then
        echo "Timeout: Indexer not ready after 10 minutes"
    else
      echo "Indexer is ready and installed..."  
    fi
{{- end -}}
