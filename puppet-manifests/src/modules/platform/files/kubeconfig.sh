# Check for interactive bash and that we haven't already been sourced.
[ -z "$PS1" -o -n "$KUBECONFIG" ] && return

# Set up the location of the k8s config file for anyone who can read it.
if [ -r /etc/kubernetes/admin.conf ]; then
    export KUBECONFIG=/etc/kubernetes/admin.conf
fi
