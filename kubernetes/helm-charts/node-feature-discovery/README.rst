kubernetes-sigs/node-feature-discovery
======================================

This chart runs v0.3.0 of the node-feature-discovery as implemented
at https://github.com/kubernetes-sigs/node-feature-discovery

This software enables node feature discovery for Kubernetes. It detects
hardware features available on each node in a Kubernetes cluster, and
advertises those features using node labels.

This chart uses a DaemonSet to spawn a pod on each node in the cluster
to do the actual work.

The two files under the templates directory are taken directly from
v0.3.0 at the link above.  The Docker image specified is the one
published by the upstream team.

