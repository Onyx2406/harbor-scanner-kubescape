{{/*
Expand the name of the chart.
*/}}
{{- define "harbor-scanner-kubescape.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "harbor-scanner-kubescape.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "harbor-scanner-kubescape.labels" -}}
helm.sh/chart: {{ include "harbor-scanner-kubescape.name" . }}
{{ include "harbor-scanner-kubescape.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "harbor-scanner-kubescape.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harbor-scanner-kubescape.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
