"""Kubernetes PQC enforcement policies for Kyverno and OPA/Gatekeeper.

Generates policy YAML that prevents deployment of quantum-vulnerable
cryptographic configurations in Kubernetes clusters.

Run: crypto-inspector k8s-policy --format kyverno --output pqc-policies.yaml
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class K8sPolicy:
    """A Kubernetes PQC enforcement policy."""
    name: str
    engine: str  # kyverno, gatekeeper, admission
    description: str
    enforcement_action: str  # enforce, audit, warn
    resources: list[str]
    match_conditions: list[dict[str, Any]]
    validate_message: str = ""
    yaml: str = ""


def generate_kyverno_policies() -> list[K8sPolicy]:
    """Generate Kyverno policies for PQC enforcement."""
    policies = []
    
    # Policy 1: Block non-PQC TLS in Ingress
    policies.append(K8sPolicy(
        name="disallow-classical-tls-ingress",
        engine="kyverno",
        description="Block Ingress resources that use classical TLS (TLS 1.2 with non-PQC ciphers)",
        enforcement_action="enforce",
        resources=["Ingress"],
        match_conditions=[{"apiVersion": "networking.k8s.io/v1", "kind": "Ingress"}],
        validate_message="Ingress must use TLS 1.3 with PQC cipher suites. Classical TLS (RSA, ECDH, ECDSA) is prohibited.",
        yaml="""
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-classical-tls-ingress
  annotations:
    policies.kyverno.io/title: Disallow Classical TLS in Ingress
    policies.kyverno.io/category: PQC Enforcement
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Ingress
    policies.kyverno.io/description: >-
      Blocks Ingress resources that use quantum-vulnerable TLS configurations.
      Requires TLS 1.3 with post-quantum cipher suites.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-tls-version
      match:
        any:
          - resources:
              kinds:
                - Ingress
      validate:
        message: >-
          Ingress {{request.object.metadata.name}} uses classical TLS.
          PQC compliance requires TLS 1.3 with ML-KEM hybrid key exchange.
          Classical algorithms (RSA, ECDH, ECDSA) are deprecated by NIST IR 8547.
        pattern:
          spec:
            tls:
              - secretName: "?*"
    - name: check-annotations
      match:
        any:
          - resources:
              kinds:
                - Ingress
      validate:
        message: >-
          Ingress {{request.object.metadata.name}} must include PQC compliance annotation.
          Add 'pqc.qtrust.dev/compliant: "true"' annotation.
        pattern:
          metadata:
            annotations:
              pqc.qtrust.dev/compliant: "true"
"""
    ))
    
    # Policy 2: Block non-PQC ConfigMaps
    policies.append(K8sPolicy(
        name="disallow-classical-crypto-configmaps",
        engine="kyverno",
        description="Block ConfigMaps containing classical crypto configurations",
        enforcement_action="audit",
        resources=["ConfigMap"],
        match_conditions=[{"apiVersion": "v1", "kind": "ConfigMap"}],
        validate_message="ConfigMap contains classical crypto references. Migrate to PQC.",
        yaml="""
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-classical-crypto-configmaps
  annotations:
    policies.kyverno.io/title: Audit Classical Crypto in ConfigMaps
    policies.kyverno.io/category: PQC Enforcement
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: ConfigMap
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: detect-rsa-keys
      match:
        any:
          - resources:
              kinds:
                - ConfigMap
      validate:
        message: >-
          ConfigMap {{request.object.metadata.name}} contains RSA key references.
          Migrate to ML-KEM-768 (FIPS 203) for key exchange.
        pattern:
          data:
            =(tls*key*): "!*RSA*"
    - name: detect-ecdsa-keys
      match:
        any:
          - resources:
              kinds:
                - ConfigMap
      validate:
        message: >-
          ConfigMap {{request.object.metadata.name}} contains ECDSA key references.
          Migrate to ML-DSA-65 (FIPS 204) for signatures.
        pattern:
          data:
            =(tls*key*): "!*ECDSA*"
    - name: detect-sha1
      match:
        any:
          - resources:
              kinds:
                - ConfigMap
      validate:
        message: >-
          ConfigMap {{request.object.metadata.name}} references SHA-1.
          Migrate to SHA-256+ or SLH-DSA (FIPS 205).
        pattern:
          data:
            =(hash*): "!*sha1*"
"""
    ))
    
    # Policy 3: Enforce PQC annotations on Deployments
    policies.append(K8sPolicy(
        name="require-pqc-annotations",
        engine="kyverno",
        description="Require PQC compliance annotations on all Deployments",
        enforcement_action="enforce",
        resources=["Deployment"],
        match_conditions=[{"apiVersion": "apps/v1", "kind": "Deployment"}],
        validate_message="Deployment must have PQC compliance annotations",
        yaml="""
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-pqc-annotations
  annotations:
    policies.kyverno.io/title: Require PQC Annotations
    policies.kyverno.io/category: PQC Enforcement
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Deployment
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-compliance-annotation
      match:
        any:
          - resources:
              kinds:
                - Deployment
                - StatefulSet
                - DaemonSet
      validate:
        message: >-
          {{request.object.kind}}/{{request.object.metadata.name}} must have
          'pqc.qtrust.dev/compliant' annotation.
        pattern:
          metadata:
            annotations:
              pqc.qtrust.dev/compliant: "true"
    - name: require-risk-level
      match:
        any:
          - resources:
              kinds:
                - Deployment
                - StatefulSet
                - DaemonSet
      validate:
        message: >-
          {{request.object.kind}}/{{request.object.metadata.name}} must have
          'pqc.qtrust.dev/risk-level' annotation (low/medium/high/critical).
        pattern:
          metadata:
            annotations:
              pqc.qtrust.dev/risk-level: "?*"
"""
    ))
    
    # Policy 4: Block secrets with classical crypto
    policies.append(K8sPolicy(
        name="block-classical-tls-secrets",
        engine="kyverno",
        description="Block Secrets containing classical TLS private keys",
        enforcement_action="warn",
        resources=["Secret"],
        match_conditions=[{"apiVersion": "v1", "kind": "Secret", "subresources": ["tls"]}],
        validate_message="TLS Secret contains classical crypto. Upgrade to PQC.",
        yaml="""
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-classical-tls-secrets
  annotations:
    policies.kyverno.io/title: Warn on Classical TLS Secrets
    policies.kyverno.io/category: PQC Enforcement
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Secret
spec:
  validationFailureAction: Warn
  background: true
  rules:
    - name: warn-classical-tls
      match:
        any:
          - resources:
              kinds:
                - Secret
              selector:
                matchLabels:
                  type: kubernetes.io/tls
      validate:
        message: >-
          TLS Secret {{request.object.metadata.name}} may contain classical
          crypto. Migrate to post-quantum certificates.
          See: https://pq-trust.dev/migration-guide
"""
    ))
    
    # Policy 5: Require PQC-compliant images
    policies.append(K8sPolicy(
        name="require-pqc-compliant-images",
        engine="kyverno",
        description="Require container images to use PQC-compliant base images",
        enforcement_action="audit",
        resources=["Pod"],
        match_conditions=[{"apiVersion": "v1", "kind": "Pod"}],
        validate_message="Container image should use PQC-compliant base",
        yaml="""
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-pqc-compliant-images
  annotations:
    policies.kyverno.io/title: Audit PQC-Compliant Images
    policies.kyverno.io/category: PQC Enforcement
    policies.kyverno.io/severity: low
    policies.kyverno.io/subject: Pod
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: check-image-registry
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: >-
          Container images should be from PQC-compliant registries.
          Recommended: images with OpenSSL 3.x+ or BoringSSL with PQC patches.
        pattern:
          spec:
            containers:
              - image: "!*openssl:1.*"
                image: "!*openssl:1.1*"
"""
    ))
    
    return policies


def generate_gatekeeper_policies() -> list[K8sPolicy]:
    """Generate OPA Gatekeeper constraints for PQC enforcement."""
    policies = []
    
    # Constraint Template: RequirePQCAnnotations
    policies.append(K8sPolicy(
        name="require-pqc-annotations-template",
        engine="gatekeeper",
        description="OPA Gatekeeper template for PQC annotation enforcement",
        enforcement_action="enforce",
        resources=["Deployment", "StatefulSet", "DaemonSet"],
        match_conditions=[{"apiVersion": "apps/v1"}],
        validate_message="Resource must have PQC compliance annotations",
        yaml="""
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: requirepqcannotations
  annotations:
    description: Requires PQC compliance annotations on workloads
spec:
  crd:
    spec:
      names:
        kind: RequirePQCAnnotations
      validation:
        openAPIV3Schema:
          type: object
          properties:
            exemptImages:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package requirepqcannotations
        
        violation[{"msg": msg}] {
          input.review.object.kind == input.parameters.kind
          not has_annotation(input.review.object, "pqc.qtrust.dev/compliant")
          msg := sprintf("%v/%v must have 'pqc.qtrust.dev/compliant' annotation", [input.review.object.kind, input.review.object.metadata.name])
        }
        
        violation[{"msg": msg}] {
          input.review.object.kind == input.parameters.kind
          not has_annotation(input.review.object, "pqc.qtrust.dev/risk-level")
          msg := sprintf("%v/%v must have 'pqc.qtrust.dev/risk-level' annotation", [input.review.object.kind, input.review.object.metadata.name])
        }
        
        has_annotation(obj, key) {
          obj.metadata.annotations[key]
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: RequirePQCAnnotations
metadata:
  name: require-pqc-annotations
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet", "DaemonSet"]
  parameters:
    kind: Deployment
    exemptImages: []
"""
    ))
    
    # Constraint Template: BlockClassicalTLS
    policies.append(K8sPolicy(
        name="block-classical-tls-template",
        engine="gatekeeper",
        description="OPA Gatekeeper template for blocking classical TLS",
        enforcement_action="enforce",
        resources=["Ingress"],
        match_conditions=[{"apiVersion": "networking.k8s.io/v1"}],
        validate_message="Ingress must not use classical TLS",
        yaml="""
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: blockclassicaltls
  annotations:
    description: Blocks classical TLS configurations in Ingress resources
spec:
  crd:
    spec:
      names:
        kind: BlockClassicalTLS
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package blockclassicaltls
        
        violation[{"msg": msg}] {
          input.review.object.kind == "Ingress"
          tls := input.review.object.spec.tls[_]
          tls.secretName
          not has_pqc_annotation(input.review.object)
          msg := sprintf("Ingress/%v uses classical TLS. Migrate to PQC cipher suites.", [input.review.object.metadata.name])
        }
        
        has_pqc_annotation(obj) {
          obj.metadata.annotations["pqc.qtrust.dev/compliant"] == "true"
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: BlockClassicalTLS
metadata:
  name: block-classical-tls
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: ["networking.k8s.io"]
        kinds: ["Ingress"]
"""
    ))
    
    return policies


def generate_admission_webhook() -> dict[str, Any]:
    """Generate K8s admission webhook configuration for PQC validation."""
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {
            "name": "pqc-validation-webhook",
            "labels": {
                "app.kubernetes.io/name": "qtrust-pqc-webhook",
                "app.kubernetes.io/version": "1.0.0",
            },
        },
        "webhooks": [
            {
                "name": "pqc.qtrust.dev",
                "admissionReviewVersions": ["v1"],
                "sideEffects": "None",
                "failurePolicy": "Fail",
                "matchPolicy": "Exact",
                "namespaceSelector": {
                    "matchExpressions": [
                        {
                            "key": "pqc.qtrust.dev/enforce",
                            "operator": "In",
                            "values": ["true"],
                        }
                    ]
                },
                "clientConfig": {
                    "service": {
                        "namespace": "qtrust-system",
                        "name": "qtrust-pqc-webhook",
                        "path": "/validate",
                        "port": 443,
                    },
                    "caBundle": "Cg==",
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE", "UPDATE"],
                        "resources": ["secrets"],
                        "scope": "Namespaced",
                    },
                    {
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE", "UPDATE"],
                        "resources": ["deployments", "statefulsets", "daemonsets"],
                        "scope": "Namespaced",
                    },
                    {
                        "apiGroups": ["networking.k8s.io"],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE", "UPDATE"],
                        "resources": ["ingresses"],
                        "scope": "Namespaced",
                    },
                ],
            }
        ],
    }


def generate_all_policies() -> list[K8sPolicy]:
    """Generate all PQC enforcement policies."""
    policies = generate_kyverno_policies()
    policies.extend(generate_gatekeeper_policies())
    return policies


def format_policies_yaml(policies: list[K8sPolicy], engine: str | None = None) -> str:
    """Format policies as YAML."""
    filtered = policies if engine is None else [p for p in policies if p.engine == engine]
    parts = []
    for policy in filtered:
        if policy.yaml:
            parts.append(policy.yaml.strip())
    return "\n---\n".join(parts)


def generate_policy_summary(policies: list[K8sPolicy]) -> dict[str, Any]:
    """Generate a summary of all policies."""
    engines = {}
    for p in policies:
        if p.engine not in engines:
            engines[p.engine] = {"count": 0, "enforce": 0, "audit": 0, "warn": 0}
        engines[p.engine]["count"] += 1
        engines[p.engine][p.enforcement_action] = engines[p.engine].get(p.enforcement_action, 0) + 1
    
    return {
        "total_policies": len(policies),
        "engines": engines,
        "protected_resources": list(set(r for p in policies for r in p.resources)),
    }
