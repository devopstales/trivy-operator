# ClusterPolicyReport

The [ClusterPolicyReport](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report) object is a prototype object proposed by the Kubernetes policy work group. The Cluster Policy Report Custom Resource Definition (CRD) can be used as a common way to provide policy results to Kubernetes cluster administrators and users, using native tools. See the [proposal](https://docs.google.com/document/d/1nICYLkYS1RE3gJzuHOfHeAC25QIkFZfgymFjgOzMDVw/edit#) for background and details.

This objects can be visualized by the [Policy Reporter UI](../../integrations/policy-reporter/).

### Installing

Add the PolicyReport CRDs to your cluster (v1alpha2):
```yaml
kubectl create -f https://github.com/kubernetes-sigs/wg-policy-prototypes/raw/master/policy-report/crd/v1alpha2/wgpolicyk8s.io_clusterpolicyreports.yaml
```

!!! note
    If you installed the trivy-operator by the helm chart the Cluster Policy Report Custom Resource Definition is installed automatically.