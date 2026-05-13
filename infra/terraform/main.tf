# ReconX Infrastructure — Terraform Main
# Provisions Kubernetes cluster and supporting infrastructure

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }

  backend "local" {
    path = "terraform.tfstate"
  }
}

variable "environment" {
  type    = string
  default = "development"
}

variable "namespace" {
  type    = string
  default = "reconx"
}

# Create namespace
resource "kubernetes_namespace" "reconx" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "reconx"
      "environment"               = var.environment
    }
  }
}

# PostgreSQL via Helm
resource "helm_release" "postgresql" {
  name       = "reconx-postgres"
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "postgresql"
  version    = "14.0.0"
  namespace  = var.namespace

  values = [<<-EOT
    auth:
      database: reconx
      username: reconx
      password: reconx_secure_password
    primary:
      persistence:
        size: 20Gi
      resources:
        requests:
          cpu: 250m
          memory: 512Mi
  EOT
  ]

  depends_on = [kubernetes_namespace.reconx]
}

# Redis via Helm
resource "helm_release" "redis" {
  name       = "reconx-redis"
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "redis"
  version    = "18.0.0"
  namespace  = var.namespace

  values = [<<-EOT
    architecture: standalone
    auth:
      enabled: false
    master:
      persistence:
        size: 5Gi
  EOT
  ]

  depends_on = [kubernetes_namespace.reconx]
}

# Elasticsearch via Helm
resource "helm_release" "elasticsearch" {
  name       = "reconx-es"
  repository = "https://helm.elastic.co"
  chart      = "elasticsearch"
  version    = "8.5.1"
  namespace  = var.namespace

  values = [<<-EOT
    replicas: 1
    minimumMasterNodes: 1
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
    volumeClaimTemplate:
      resources:
        requests:
          storage: 30Gi
  EOT
  ]

  depends_on = [kubernetes_namespace.reconx]
}

# Monitoring stack
resource "helm_release" "prometheus_stack" {
  name       = "monitoring"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = "56.0.0"
  namespace  = "reconx-monitoring"

  values = [<<-EOT
    grafana:
      adminPassword: admin
      ingress:
        enabled: true
        hosts:
          - grafana.reconx.local
    prometheus:
      prometheusSpec:
        retention: 7d
        storageSpec:
          volumeClaimTemplate:
            spec:
              resources:
                requests:
                  storage: 20Gi
  EOT
  ]
}

output "namespace" {
  value = kubernetes_namespace.reconx.metadata[0].name
}
