{{/*
Unqualified chart name for app.kubernetes.io/name.
*/}}
{{- define "weissman.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Per-customer namespace. Defaults to weissman-<customer.name>; override with namespace.name.
Every namespaced resource pins metadata.namespace to this, so the namespace passed with
`helm install -n <ns>` MUST equal this value (Helm errors loudly on a mismatch).
*/}}
{{- define "weissman.namespace" -}}
{{- $c := required "customer.name is required (a DNS-label-safe id, e.g. acme)" .Values.customer.name -}}
{{- default (printf "weissman-%s" $c) .Values.namespace.name -}}
{{- end -}}

{{/*
Name of the Secret holding all connection strings and at-rest keys.
*/}}
{{- define "weissman.secretName" -}}
{{- default "weissman-secrets" .Values.secrets.name -}}
{{- end -}}

{{/*
Name of the ConfigMap holding non-secret runtime config.
*/}}
{{- define "weissman.configName" -}}
{{- default "weissman-config" .Values.config.name -}}
{{- end -}}

{{/*
Fully-resolved backend/worker image reference. Prefer an immutable, cosign-verified digest.
*/}}
{{- define "weissman.image" -}}
{{- $repo := required "image.repository is required" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/*
Common metadata labels applied to every resource.
*/}}
{{- define "weissman.labels" -}}
app.kubernetes.io/name: {{ include "weissman.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: weissman-cybersecurity
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | toString | replace "+" "_") }}
weissman.io/tier: dedicated
weissman.io/customer: {{ required "customer.name is required" .Values.customer.name | quote }}
{{- with .Values.customer.region }}
weissman.io/region: {{ . | quote }}
{{- end }}
{{- with .Values.customer.sizing }}
weissman.io/sizing: {{ . | quote }}
{{- end }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}
