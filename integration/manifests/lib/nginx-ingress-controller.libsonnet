{
  apiVersion: 'v1',
  kind: 'List',
  items: [
    {
      apiVersion: 'v1',
      kind: 'Namespace',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'ingress-nginx' },
    },
    {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'nginx-configuration', namespace: 'ingress-nginx' },
    },
    {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'tcp-services', namespace: 'ingress-nginx' },
    },
    {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'udp-services', namespace: 'ingress-nginx' },
    },
    {
      apiVersion: 'v1',
      kind: 'ServiceAccount',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'nginx-ingress-serviceaccount', namespace: 'ingress-nginx' },
    },
    {
      apiVersion: 'rbac.authorization.k8s.io/v1beta1',
      kind: 'ClusterRole',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'nginx-ingress-clusterrole' },
      rules: [{ apiGroups: [''], resources: ['configmaps', 'endpoints', 'nodes', 'pods', 'secrets'], verbs: ['list', 'watch'] }, { apiGroups: [''], resources: ['nodes'], verbs: ['get'] }, { apiGroups: [''], resources: ['services'], verbs: ['get', 'list', 'watch'] }, { apiGroups: [''], resources: ['events'], verbs: ['create', 'patch'] }, { apiGroups: ['extensions', 'networking.k8s.io'], resources: ['ingresses'], verbs: ['get', 'list', 'watch'] }, { apiGroups: ['extensions', 'networking.k8s.io'], resources: ['ingresses/status'], verbs: ['update'] }],
    },
    {
      apiVersion: 'rbac.authorization.k8s.io/v1beta1',
      kind: 'Role',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'nginx-ingress-role', namespace: 'ingress-nginx' },
      rules: [{ apiGroups: [''], resources: ['configmaps', 'pods', 'secrets', 'namespaces'], verbs: ['get'] }, { apiGroups: [''], resourceNames: ['ingress-controller-leader-nginx'], resources: ['configmaps'], verbs: ['get', 'update'] }, { apiGroups: [''], resources: ['configmaps'], verbs: ['create'] }, { apiGroups: [''], resources: ['endpoints'], verbs: ['get'] }],
    },
    {
      apiVersion: 'rbac.authorization.k8s.io/v1beta1',
      kind: 'RoleBinding',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'nginx-ingress-role-nisa-binding', namespace: 'ingress-nginx' },
      roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: 'nginx-ingress-role' },
      subjects: [{ kind: 'ServiceAccount', name: 'nginx-ingress-serviceaccount', namespace: 'ingress-nginx' }],
    },
    {
      apiVersion: 'rbac.authorization.k8s.io/v1beta1',
      kind: 'ClusterRoleBinding',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'nginx-ingress-clusterrole-nisa-binding' },
      roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'nginx-ingress-clusterrole' },
      subjects: [{ kind: 'ServiceAccount', name: 'nginx-ingress-serviceaccount', namespace: 'ingress-nginx' }],
    },
    {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'nginx-ingress-controller', namespace: 'ingress-nginx' },
      spec: {
        replicas: 1,
        selector: { matchLabels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' } },
        template: {
          metadata: { annotations: { 'prometheus.io/port': '10254', 'prometheus.io/scrape': 'true' }, labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' } },
          spec: {
            containers: [{
              name: 'nginx-ingress-controller',
              image: 'quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.30.0',
              args: [
                '/nginx-ingress-controller',
                '--configmap=$(POD_NAMESPACE)/nginx-configuration',
                '--tcp-services-configmap=$(POD_NAMESPACE)/tcp-services',
                '--udp-services-configmap=$(POD_NAMESPACE)/udp-services',
                '--publish-service=$(POD_NAMESPACE)/ingress-nginx',
                '--annotations-prefix=nginx.ingress.kubernetes.io',
                '--v=2',
              ],
              env: [
                { name: 'POD_NAME', valueFrom: { fieldRef: { fieldPath: 'metadata.name' } } },
                { name: 'POD_NAMESPACE', valueFrom: { fieldRef: { fieldPath: 'metadata.namespace' } } },
              ],
              lifecycle: { preStop: { exec: { command: ['/wait-shutdown'] } } },
              livenessProbe: { failureThreshold: 3, httpGet: { path: '/healthz', port: 10254, scheme: 'HTTP' }, initialDelaySeconds: 10, periodSeconds: 10, successThreshold: 1, timeoutSeconds: 10 },
              ports: [{ containerPort: 80, name: 'http', protocol: 'TCP' }, { containerPort: 443, name: 'https', protocol: 'TCP' }],
              readinessProbe: { failureThreshold: 3, httpGet: { path: '/healthz', port: 10254, scheme: 'HTTP' }, periodSeconds: 10, successThreshold: 1, timeoutSeconds: 10 },
              securityContext: { allowPrivilegeEscalation: true, capabilities: { add: ['NET_BIND_SERVICE'], drop: ['ALL'] }, runAsUser: 101 },
            }],
            nodeSelector: { 'kubernetes.io/os': 'linux' },
            serviceAccountName: 'nginx-ingress-serviceaccount',
            terminationGracePeriodSeconds: 300,
          },
        },
      },
    },
    {
      apiVersion: 'v1',
      kind: 'LimitRange',
      metadata: { labels: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' }, name: 'ingress-nginx', namespace: 'ingress-nginx' },
      spec: { limits: [{ min: { cpu: '100m', memory: '90Mi' }, type: 'Container' }] },
    },
    {
      apiVersion: 'v1',
      kind: 'Service',
      metadata: {
        namespace: 'ingress-nginx',
        name: 'ingress-nginx',
        labels: {
          'app.kubernetes.io/name': 'ingress-nginx',
          'app.kubernetes.io/part-of': 'ingress-nginx',
        },
      },
      spec: {
        type: 'ClusterIP',
        clusterIP: '10.96.1.1',
        selector: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' },
        ports: [
          { name: 'http', port: 80, protocol: 'TCP', targetPort: 'http' },
          { name: 'https', port: 443, protocol: 'TCP', targetPort: 'https' },
        ],
      },
    },
    {
      apiVersion: 'v1',
      kind: 'Service',
      metadata: {
        namespace: 'ingress-nginx',
        name: 'ingress-nginx-nodeport',
        labels: {
          'app.kubernetes.io/name': 'ingress-nginx',
          'app.kubernetes.io/part-of': 'ingress-nginx',
        },
      },
      spec: {
        type: 'NodePort',
        selector: { 'app.kubernetes.io/name': 'ingress-nginx', 'app.kubernetes.io/part-of': 'ingress-nginx' },
        ports: [
          { name: 'http', port: 80, protocol: 'TCP', targetPort: 'http', nodePort: 30080 },
          { name: 'https', port: 443, protocol: 'TCP', targetPort: 'https', nodePort: 30443 },
        ],
      },
    },
  ],
}
