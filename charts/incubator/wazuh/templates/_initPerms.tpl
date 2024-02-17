{{- define "wazuh.init.perms" -}}
{{- $uid := .Values.securityContext.container.runAsUser -}}
{{- $gid := .Values.securityContext.container.runAsGroup -}}
{{- $fsGroup := .Values.securityContext.container.fsGroup -}}
enabled: true
type: install
imageSelector: alpineImage
securityContext:
  runAsUser: 0
  runAsGroup: {{ $gid }}
  runAsNonRoot: true
  readOnlyRootFilesystem: false
  fsGroup: {{ $fsGroup }}
command: /bin/sh
args:
  - -c
  - |
    mkdir -p /tmp/wazuh/certs
    cp -r /bad-ownership-cert/* /tmp/wazuh/certs

    # Set UMASK so newly created file will have permissions 400
    umask 377

    # Source directory
    source_dir="/tmp/wazuh/certs"

    # Destination directories
    destinations="/wazuh-indexer-certs /wazuh-dashboard-certs /wazuh-manager-certs"
    
    for dest in $destinations; 
    do 
      # Extract the second word using cut and store it in a variable
      service=$(echo "${dest}" | cut -d'-' -f2)

      # Write root-ca
      cat "${source_dir}/general/root-ca.pem" > "${dest}/root-ca.pem" ; 

      find "${source_dir}/${service}" -type f -exec sh -c 'cat "$0" > "/wazuh-${1}-certs/$(basename "$0")"' {} "$service" \;
    done

    apk add openssl -q --no-interactive

    openssl pkcs8 -topk8 -inform PEM -in /wazuh-indexer-certs/admin-key.pem -out /wazuh-indexer-certs/admin.key -nocrypt

    mkdir -p /tmp/wazuh/conf
    cp -r /bad-ownership-conf/* /tmp/wazuh/conf

    # Set UMASK so newly created file will have permissions 600
    umask 177

    # Source directory
    source_dir="/tmp/wazuh/conf"

    # Destination directories
    destinations="/wazuh-indexer-conf /wazuh-dashboard-conf /wazuh-manager-conf"
    
    for dest in $destinations; 
    do 
      # Extract the second word using cut and store it in a variable
      service=$(echo "${dest}" | cut -d'-' -f2)

      find "${source_dir}/${service}" -type f -exec sh -c 'cat "$0" > "/wazuh-${1}-conf/$(basename "$0")"' {} "$service" \;
    done

    chown -R {{ $uid }}:{{ $gid }} /wazuh-*

    echo "Indexer:" && \
    echo "    Cert:" && \
    ls -la /wazuh-indexer-certs/ && \

    echo "Dashboard:" && \
    echo "    Cert:" && \
    ls -la /wazuh-dashboard-certs/ && \

    echo "Manager:" && \
    echo "    Cert:" && \
    ls -la /wazuh-manager-certs/
{{- end -}}