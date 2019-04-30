{{/*
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

{
  "apiVersion": "apps/v1",
  "kind": "DaemonSet",
  "metadata": {
    "labels": {
      "app": {{ .Values.app_label }}
    },
    "namespace": {{ .Values.namespace }},
    "name": {{ .Release.Name }}
  },
  "spec": {
    "selector": {
      "matchLabels": {
        "app": {{ .Values.app_label }}
      }
    },
    "template": {
      "metadata": {
        "labels": {
          "app": {{ .Values.app_label }}
        }
      },
      "spec": {
{{ if and .Values.node_selector_key  .Values.node_selector_value }}
        "nodeSelector": {
          {{ .Values.node_selector_key }}: {{ .Values.node_selector_value }}
        },
{{ end }}
        "hostNetwork": true,
        "serviceAccount": {{ .Release.Name }},
        "containers": [
          {
            "env": [
              {
                "name": "NODE_NAME",
                "valueFrom": {
                  "fieldRef": {
                    "fieldPath": "spec.nodeName"
                  }
                }
              }
            ],
            "image": "quay.io/kubernetes_incubator/node-feature-discovery:v0.3.0",
            "name": {{ .Release.Name }},
            "args": ["--sleep-interval={{ .Values.scan_interval }}s"],
            "volumeMounts": [
              {
                "name": "host-sys",
                "mountPath": "/host-sys"
              }
            ]
          }
        ],
        "volumes": [
          {
            "name": "host-sys",
            "hostPath": {
              "path": "/sys"
            }
          }
        ]
      }
    }
  }
}
