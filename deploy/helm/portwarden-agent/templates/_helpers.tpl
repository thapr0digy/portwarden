{{- define "portwarden-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "portwarden-agent.labels" -}}
app.kubernetes.io/name: {{ include "portwarden-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "portwarden-agent.selector" -}}
app.kubernetes.io/name: {{ include "portwarden-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
