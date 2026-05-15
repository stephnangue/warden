{{/*
Common chart helpers.
*/}}

{{- define "warden.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "warden.fullname" -}}
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

{{- define "warden.headlessName" -}}
{{- printf "%s-headless" (include "warden.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "warden.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels — applied to every object the chart renders.
*/}}
{{- define "warden.labels" -}}
helm.sh/chart: {{ include "warden.chart" . }}
{{ include "warden.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels — stable across upgrades; used by Services and the
StatefulSet's pod template selector.
*/}}
{{- define "warden.selectorLabels" -}}
app.kubernetes.io/name: {{ include "warden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "warden.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "warden.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Name of the chart-managed Secret that holds the postgres connection URL
and the seal token, when literal values were provided in values.yaml.
Existing user Secrets are referenced by name directly and bypass this.
*/}}
{{- define "warden.credentialsSecretName" -}}
{{- printf "%s-credentials" (include "warden.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
True when the chart needs to create its own credentials Secret because
the user passed a literal connectionUrl or token rather than an
existingSecret reference.
*/}}
{{- define "warden.needsCredentialsSecret" -}}
{{- $needPg := and (eq (.Values.storage.existingSecret | default "") "") (ne (.Values.storage.connectionUrl | default "") "") -}}
{{- $needTransit := and (eq .Values.seal.type "transit") (and (eq (.Values.seal.transit.existingSecret | default "") "") (ne (.Values.seal.transit.token | default "") "")) -}}
{{- if or $needPg $needTransit -}}true{{- end -}}
{{- end -}}

{{/*
warden.preflight enforces fail-fast on values that cannot be deferred
to runtime — calling this from statefulset.yaml (always rendered) makes
helm install / helm template fail with an actionable message instead of
producing manifests that crash-loop at pod startup.
*/}}
{{- define "warden.preflight" -}}
{{- if not .Values.tls.existingSecret -}}
{{- fail "tls.existingSecret is required: create a kubernetes.io/tls Secret and pass --set tls.existingSecret=<name>" -}}
{{- end -}}
{{- if not (or .Values.storage.existingSecret .Values.storage.connectionUrl) -}}
{{- fail "Either storage.existingSecret or storage.connectionUrl must be set so the postgres connection URL can be sourced" -}}
{{- end -}}
{{- if eq .Values.seal.type "transit" -}}
{{- if not .Values.seal.transit.address -}}
{{- fail "seal.transit.address is required when seal.type=transit" -}}
{{- end -}}
{{- if not .Values.seal.transit.keyName -}}
{{- fail "seal.transit.keyName is required when seal.type=transit" -}}
{{- end -}}
{{- if not (or .Values.seal.transit.existingSecret .Values.seal.transit.token) -}}
{{- fail "Either seal.transit.existingSecret or seal.transit.token must be set when seal.type=transit" -}}
{{- end -}}
{{- else if eq .Values.seal.type "static" -}}
{{- if not .Values.seal.static.existingSecret -}}
{{- fail "seal.static.existingSecret is required when seal.type=static — reference a Secret containing the seal key" -}}
{{- end -}}
{{- else -}}
{{- fail (printf "seal.type must be 'transit' or 'static', got %q" .Values.seal.type) -}}
{{- end -}}
{{- end -}}

{{/*
Per-pod api_addr / cluster_addr templates. The HCL is rendered at
warden boot through the env-interpolation pass added in PR 1, so
{{ env "POD_NAME" }} resolves to the actual pod name. The chart's
two outer {{`...`}} keep the inner braces literal in the rendered
ConfigMap.
*/}}
{{- define "warden.apiAddrTemplate" -}}
https://{{`{{ env "POD_NAME" }}`}}.{{ include "warden.headlessName" . }}.{{ .Release.Namespace }}.svc.cluster.local:8400
{{- end -}}

{{- define "warden.clusterAddrTemplate" -}}
https://{{`{{ env "POD_NAME" }}`}}.{{ include "warden.headlessName" . }}.{{ .Release.Namespace }}.svc.cluster.local:8401
{{- end -}}
