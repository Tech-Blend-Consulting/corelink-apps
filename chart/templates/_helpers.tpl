{{- define "corelink.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "corelink.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The ServiceAccount the server pods run as: the created one, the named one, or empty (the namespace default). */}}
{{- define "corelink.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "corelink.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "corelink.selectorLabels" -}}
app.kubernetes.io/name: {{ include "corelink.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "corelink.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "corelink.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "corelink.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/* The Secret holding DATABASE_PASSWORD, JWT_SECRET and SESSION_SECRET. */}}
{{- define "corelink.secretName" -}}
{{- default (printf "%s-secrets" (include "corelink.fullname" .)) .Values.existingSecret -}}
{{- end -}}

{{/* The Secret holding the database CA as ca.pem; empty when there is none. */}}
{{- define "corelink.dbCASecret" -}}
{{- if .Values.database.sslRootCert.secretName -}}
{{- .Values.database.sslRootCert.secretName -}}
{{- else if .Values.database.sslRootCert.pem -}}
{{- printf "%s-db-ca" (include "corelink.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* "true" when the server runs as more than one pod; empty otherwise. */}}
{{- define "corelink.scaled" -}}
{{- if or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled -}}true{{- end -}}
{{- end -}}

{{- define "corelink.pgbouncerName" -}}
{{- printf "%s-pgbouncer" (include "corelink.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Connections PgBouncer may open to PostgreSQL: pgbouncer.poolSize, or one
full application pool per replica. In session mode a client holds its server
connection for as long as it is connected, so this is also the ceiling on what
the servers can use between them. */}}
{{- define "corelink.pgbouncerPoolSize" -}}
{{- if gt (int .Values.pgbouncer.poolSize) 0 -}}
{{- int .Values.pgbouncer.poolSize -}}
{{- else -}}
{{- $replicas := int .Values.replicaCount -}}
{{- if .Values.autoscaling.enabled -}}
{{- $replicas = int .Values.autoscaling.maxReplicas -}}
{{- end -}}
{{- mul $replicas (int .Values.database.maxOpenConns) -}}
{{- end -}}
{{- end -}}

{{/* Chart-created objects the migrate hook needs must exist before it runs. */}}
{{- define "corelink.hookAnnotations" -}}
"helm.sh/hook": pre-install,pre-upgrade
"helm.sh/hook-weight": {{ .weight | quote }}
"helm.sh/hook-delete-policy": before-hook-creation
{{- end -}}

{{/* The non-secret settings, as KEY: "value" lines. */}}
{{- define "corelink.config" -}}
ENVIRONMENT: {{ .Values.config.environment | quote }}
CORELINK_SELF_HOSTED: "true"
{{- if .Values.persistence.enabled }}
CORELINK_LICENSE_FILE: /app/data/license.json
{{- end }}
LOGLEVEL: {{ .Values.config.logLevel | quote }}
PORT: "8080"
OAUTH_BASEURL: {{ .Values.config.publicUrl | quote }}
CORS_ALLOWEDORIGINS: {{ default .Values.config.publicUrl .Values.config.corsAllowedOrigins | quote }}
CORS_ALLOWCREDENTIALS: "true"
SESSION_SECURE: "true"
SESSION_HTTPONLY: "true"
SESSION_SAMESITE: Lax
SECURITY_TRUSTED_PROXY_CIDRS: {{ .Values.config.trustedProxyCidrs | quote }}
{{- if .Values.pgbouncer.enabled }}
DATABASE_HOST: {{ include "corelink.pgbouncerName" . | quote }}
DATABASE_PORT: "5432"
DATABASE_POOL_MODE: session
{{- else }}
DATABASE_HOST: {{ .Values.database.host | quote }}
DATABASE_PORT: {{ .Values.database.port | quote }}
{{- end }}
DATABASE_USER: {{ .Values.database.user | quote }}
DATABASE_NAME: {{ .Values.database.name | quote }}
DATABASE_SSLMODE: {{ .Values.database.sslmode | quote }}
{{- if include "corelink.dbCASecret" . }}
DATABASE_SSLROOTCERT: /app/certs/ca.pem
{{- end }}
DATABASE_AUTOMIGRATE: "false"
DATABASE_MAXOPENCONNS: {{ .Values.database.maxOpenConns | quote }}
DATABASE_MAXIDLECONNS: {{ .Values.database.maxIdleConns | quote }}
DATABASE_CONNMAXLIFETIME: {{ .Values.database.connMaxLifetime | quote }}
JWT_ACCESSEXPIRY: 15m
JWT_REFRESHEXPIRY: 168h
KMS_PROVIDER: {{ .Values.kms.provider | quote }}
{{- if eq .Values.kms.provider "local" }}
KMS_LOCAL_KEK_FILE: /app/data/kek.key
{{- end }}
{{- if eq .Values.kms.provider "gcp" }}
{{- if not .Values.kms.gcp.project }}{{ fail "kms.gcp.project must be set when kms.provider=gcp" }}{{ end }}
{{- if not .Values.kms.gcp.location }}{{ fail "kms.gcp.location must be set when kms.provider=gcp" }}{{ end }}
{{- if not .Values.kms.gcp.keyRing }}{{ fail "kms.gcp.keyRing must be set when kms.provider=gcp" }}{{ end }}
{{- if not .Values.kms.gcp.keyName }}{{ fail "kms.gcp.keyName must be set when kms.provider=gcp" }}{{ end }}
KMS_GCP_PROJECT: {{ .Values.kms.gcp.project | quote }}
KMS_GCP_LOCATION: {{ .Values.kms.gcp.location | quote }}
KMS_GCP_KEYRING: {{ .Values.kms.gcp.keyRing | quote }}
KMS_GCP_KEYNAME: {{ .Values.kms.gcp.keyName | quote }}
{{- end }}
RATELIMIT_ENABLED: "true"
{{- if and .Values.autoscaling.requestsPerSecond.enabled (not (hasKey .Values.config.extra "METRICS_BIND")) }}
METRICS_BIND: "0.0.0.0:9090"
{{- end }}
{{- range $k, $v := .Values.config.extra }}
{{ $k }}: {{ $v | quote }}
{{- end }}
{{- end -}}
