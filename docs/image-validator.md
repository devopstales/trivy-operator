# Trivy Image Validator

## Admission Controller
The admission controller function can be configured as a ValidatingWebhook in a k8s cluster. Kubernetes will send requests to the admission server when a Pod creation is initiated. The admission controller checks the image using trivy if it is in a namespace with the label `trivy-operator-validation=true`.

## Example Deploy:
You can define policy to the Admission Controller, by adding annotation to the pod trough the deployment:

```
spec:
  ...
  template:
    metadata:
      annotations:
        trivy.security.devopstales.io/medium: "5"
        trivy.security.devopstales.io/low: "10"
        trivy.security.devopstales.io/critical: "2"
...
```