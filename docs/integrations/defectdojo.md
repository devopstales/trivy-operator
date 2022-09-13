# DefectDojo

## Install with Helm chart

```bash
helm repo add defectdojo 'https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/helm-charts'
helm repo update

helm upgrade --install \
  defectdojo \
  defectdojo/defectdojo \
  --set django.ingress.enabled=true \
  --set django.ingress.activateTLS=false \
  --set createSecret=true \
  --set createRabbitMqSecret=true \
  --set createRedisSecret=true \
  --set createMysqlSecret=true \
  --set createPostgresqlSecret=true \
  --set host=defectdojo.k8s.intra
```

To find out the password, run the following command:

```bash
echo "DefectDojo admin password: $(kubectl \
  get secret defectdojo \
  --output jsonpath='{.data.DD_ADMIN_PASSWORD}' \
  | base64 --decode)"
```