# Azure deployment guide

This guide deploys the IPsec Analyzer as one Azure Container App containing
three tightly coupled containers:

```text
Internet -> HTTPS Azure ingress -> Next.js :3000
                                  |-> Go Core :8080
                                      |-> Python ML gRPC :50051
                                  |-> Azure Files /var/lib/alchemist/reports
```

Only Next.js is public. Core is reached through the same-origin `/api/core`
proxy and the ML worker remains private. All three containers share a network
namespace and therefore use `127.0.0.1` internally. Azure scales them as one
unit, which matches the current in-memory analysis store.

The commands below use Bash in Azure Cloud Shell or a local shell with a recent
Azure CLI. Microsoft documents the underlying features in its guides for
[ACR Tasks](https://learn.microsoft.com/azure/container-registry/container-registry-quickstart-task-cli),
[multi-container Container Apps](https://learn.microsoft.com/azure/container-apps/containers),
[Container Apps ingress](https://learn.microsoft.com/azure/container-apps/ingress-overview),
and [Azure Files mounts](https://learn.microsoft.com/azure/container-apps/storage-mounts).

## 1. Prerequisites

- An Azure subscription where you can create resource groups, role assignments,
  Container Apps, ACR, and Storage resources.
- Azure CLI logged in with `az login`.
- Run commands from the repository root.
- Choose a globally unique, lowercase ACR name and storage-account name.

Install/update the required extension and providers:

```bash
az extension add --name containerapp --upgrade
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights
az provider register --namespace Microsoft.ContainerRegistry
az provider register --namespace Microsoft.Storage
```

Set deployment variables. Change the two globally unique names:

```bash
RESOURCE_GROUP="alchemist-prod-rg"
LOCATION="centralindia"
CONTAINER_ENV="alchemist-prod-env"
CONTAINER_APP="alchemist"
ACR_NAME="changealchemistacr"
STORAGE_ACCOUNT="changealchemiststore"
FILE_SHARE="reports"
STORAGE_LINK="alchemistreports"
PULL_IDENTITY="alchemist-acr-pull"
IMAGE_TAG="v1"
```

Never reuse these shell variables for another deployment in the same terminal.

## 2. Create the Azure foundation

```bash
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

az acr create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACR_NAME" \
  --sku Basic

az containerapp env create \
  --name "$CONTAINER_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION"
```

Create a user-assigned identity for image pulls, grant only `AcrPull`, and keep
its resource ID for the YAML file:

```bash
PULL_IDENTITY_ID=$(az identity create \
  --name "$PULL_IDENTITY" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --query id -o tsv)

PULL_PRINCIPAL_ID=$(az identity show \
  --name "$PULL_IDENTITY" \
  --resource-group "$RESOURCE_GROUP" \
  --query principalId -o tsv)

ACR_ID=$(az acr show --name "$ACR_NAME" --query id -o tsv)

az role assignment create \
  --assignee-object-id "$PULL_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role AcrPull \
  --scope "$ACR_ID"
```

Role assignment propagation can take several minutes. Do not enable the ACR
admin account; the Container App pulls using this managed identity.

## 3. Build all three images in ACR

ACR Tasks builds remotely and pushes each resulting image to your private
registry:

```bash
az acr build \
  --registry "$ACR_NAME" \
  --image "alchemist/core:$IMAGE_TAG" \
  --file backend/Dockerfile \
  backend

az acr build \
  --registry "$ACR_NAME" \
  --image "alchemist/ml:$IMAGE_TAG" \
  --file backend/ml-service/Dockerfile \
  backend/ml-service

az acr build \
  --registry "$ACR_NAME" \
  --image "alchemist/frontend:$IMAGE_TAG" \
  --file frontend/Dockerfile \
  frontend
```

Use an immutable tag such as a release number or Git SHA for real releases.
Avoid `latest`, because it makes rollback and audit difficult.

## 4. Create and link persistent Azure Files storage

The report artifact directory is mounted from Azure Files. This survives
container revisions and replica restarts:

```bash
az storage account create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$STORAGE_ACCOUNT" \
  --location "$LOCATION" \
  --kind StorageV2 \
  --sku Standard_LRS \
  --enable-large-file-share

az storage share-rm create \
  --resource-group "$RESOURCE_GROUP" \
  --storage-account "$STORAGE_ACCOUNT" \
  --name "$FILE_SHARE" \
  --quota 100 \
  --enabled-protocols SMB

STORAGE_KEY=$(az storage account keys list \
  --resource-group "$RESOURCE_GROUP" \
  --account-name "$STORAGE_ACCOUNT" \
  --query '[0].value' -o tsv)

az containerapp env storage set \
  --name "$CONTAINER_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --storage-name "$STORAGE_LINK" \
  --storage-type AzureFile \
  --azure-file-account-name "$STORAGE_ACCOUNT" \
  --azure-file-account-key "$STORAGE_KEY" \
  --azure-file-share-name "$FILE_SHARE" \
  --access-mode ReadWrite

unset STORAGE_KEY
```

The environment link is named `alchemistreports`, matching
`deploy/azure-container-app.yaml`. The mount uses UID/GID 10001, the non-root
Core user in `backend/Dockerfile`.

Important: generated PDF files persist, but analysis metadata is currently held
in Go memory. After a replica restart, old reports will remain in Azure Files
but will not appear in the dashboard because the in-memory artifact index and
analyses are gone. Keep `minReplicas=1` and `maxReplicas=1` until that state is
moved to a durable database/object index.

## 5. Prepare the Container App specification

Obtain the environment resource ID:

```bash
CONTAINER_ENV_ID=$(az containerapp env show \
  --name "$CONTAINER_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --query id -o tsv)
```

Copy `deploy/azure-container-app.yaml` to a private working file, then replace:

| Placeholder | Value |
| --- | --- |
| `<ACR_NAME>` | value of `$ACR_NAME` |
| `<IMAGE_TAG>` | value of `$IMAGE_TAG` |
| `<ACR_PULL_IDENTITY_RESOURCE_ID>` | value printed by `echo "$PULL_IDENTITY_ID"` |
| `<CONTAINER_APPS_ENVIRONMENT_RESOURCE_ID>` | value printed by `echo "$CONTAINER_ENV_ID"` |
| `<APP_PUBLIC_URL>` | temporary `https://deployment.invalid` for the first deployment |
| `<STORAGE_LINK_NAME>` | value of `$STORAGE_LINK` |

Do not commit the rendered file if it contains environment-specific values.
The checked-in YAML is a reusable template and contains no secret.

Create the app from the rendered specification:

```bash
az containerapp create \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --yaml /path/to/rendered-azure-container-app.yaml
```

If the first pull reports authorization failure, wait a few minutes for the
`AcrPull` assignment to propagate, then run the create command again.

## 6. Set the real deployed URL

Read Azure's generated HTTPS URL:

```bash
APP_FQDN=$(az containerapp show \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn -o tsv)
APP_PUBLIC_URL="https://$APP_FQDN"
echo "$APP_PUBLIC_URL"
```

Update both containers that need the public origin. No source-code localhost
replacement or image rebuild is necessary:

```bash
az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --container-name frontend \
  --set-env-vars "APP_PUBLIC_URL=$APP_PUBLIC_URL"

az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --container-name core \
  --set-env-vars "CORS_ALLOWED_ORIGINS=$APP_PUBLIC_URL"
```

Use the same two updates after attaching a custom domain, replacing the value
with `https://your-domain.example`. Multiple allowed origins are comma-separated
with no wildcard. The dashboard itself remains same-origin and uses
`CORE_HTTP_URL=http://127.0.0.1:8080` inside the shared replica.

### Optional custom domain and managed TLS certificate

For a subdomain such as `vpn.example.com`, create a CNAME at your DNS provider
that points directly to `$APP_FQDN`. Also create the `asuid.vpn` TXT ownership
record shown by Azure Portal under **Container App → Custom domains**. Do not
place Cloudflare or another intermediate proxy in front while Azure issues or
renews the managed certificate.

After DNS validation, bind the domain with Azure's free managed certificate:

```bash
DOMAIN_NAME="vpn.example.com"

az containerapp hostname add \
  --hostname "$DOMAIN_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CONTAINER_APP"

az containerapp hostname bind \
  --hostname "$DOMAIN_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CONTAINER_APP" \
  --environment "$CONTAINER_ENV" \
  --validation-method CNAME

APP_PUBLIC_URL="https://$DOMAIN_NAME"

az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --container-name frontend \
  --set-env-vars "APP_PUBLIC_URL=$APP_PUBLIC_URL"

az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --container-name core \
  --set-env-vars "CORS_ALLOWED_ORIGINS=$APP_PUBLIC_URL"
```

For an apex/root domain, follow Microsoft's
[managed certificate guide](https://learn.microsoft.com/azure/container-apps/custom-domains-managed-certificates)
and use its A-record plus HTTP-validation procedure instead.

## 7. Add the optional Groq secret

Skip this section if report chat is not required. Store the key as a Container
Apps secret and reference it from the frontend environment; never place it in a
YAML file, Docker image, Git, or a `NEXT_PUBLIC_` variable:

```bash
read -s GROQ_API_KEY
az containerapp secret set \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --secrets "groq-api-key=$GROQ_API_KEY"
unset GROQ_API_KEY

az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --container-name frontend \
  --set-env-vars "GROQ_API_KEY=secretref:groq-api-key"
```

## 8. Verify the deployment

Open the URL printed in step 6 and complete this smoke test:

1. The landing page and workspace load over HTTPS.
2. Upload a classic `.pcap` or `.cap` file.
3. Start an analysis and wait for `ANALYSIS_STATE_COMPLETED`.
4. Open every dashboard section.
5. Generate and download the executive PDF from Overview.
6. Confirm the browser developer console has no mixed-content or CORS errors.

Inspect revision state and logs:

```bash
az containerapp revision list \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --output table

az containerapp logs show \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --container frontend \
  --follow

az containerapp logs show \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --container core \
  --follow

az containerapp logs show \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --container ml \
  --follow
```

Only run one `--follow` command per terminal. Core `/health` is intentionally
private behind the frontend proxy; the dashboard's system-health screen is the
browser-level verification.

## 9. Release updates and rollback

For the next release, build all three images with a new immutable tag, update
the three `image:` values in the rendered YAML, and run:

```bash
az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --yaml /path/to/rendered-azure-container-app.yaml
```

Container Apps revisions provide the release history. In single-revision mode,
re-deploy the previous known-good image tag to roll back. Do not deploy different
Core and ML contract versions independently unless their protobuf compatibility
has been verified.

## 10. Local production-like Docker verification

Copy the safe template and change values only in the ignored `.env`:

```bash
cp .env.example .env
docker compose up --build --detach
docker compose ps
curl http://127.0.0.1:8080/health
```

Open <http://localhost:3000>. Named volumes are created automatically:

- `report-data` at `/var/lib/alchemist/reports` in Core.
- `frontend-cache` at `/app/.next/cache` in Next.js.

Stop containers without deleting volumes:

```bash
docker compose down
```

To inspect the resolved configuration without printing container logs:

```bash
docker compose config
```

Do not use `docker compose down --volumes` in production; it deletes the named
volumes. Back up Azure Files according to your retention requirements.

## 11. Deployment limitations

- Azure Container Apps is suitable for offline PCAP upload and analysis.
- Live capture, XFRM inspection, and StrongSwan VICI access require Linux host
  networking, capabilities, and a host socket. Run that authorized Deep
  Assessment mode on a hardened Azure Linux VM or AKS design reviewed by your
  security team; do not grant privileged host access to this public app.
- CORS is a browser policy, not authentication. If Core is ever exposed directly,
  add identity/authentication, rate limits, upload limits, and a reverse proxy or
  API gateway. The recommended topology keeps Core private.
- The current in-memory state requires exactly one replica. Durable multi-replica
  scaling needs a database/object index plus coordinated Next.js caching.

## Environment variable reference

| Variable | Container | Purpose |
| --- | --- | --- |
| `APP_PUBLIC_URL` | frontend | Deployed dashboard URL and metadata base. |
| `CORE_HTTP_URL` | frontend | Private server-side Core HTTP endpoint. |
| `GROQ_API_KEY` | frontend | Optional secret for report chat. |
| `GROQ_MODEL` | frontend | Optional report-chat model selection. |
| `CORE_HTTP_ADDRESS` | core | HTTP bind address. Use `0.0.0.0:8080` in containers. |
| `CORE_GRPC_ADDRESS` | core | Trusted gRPC bind address. |
| `ML_GRPC_ADDRESS` | core | Private Python gRPC endpoint. |
| `REPORT_TEMP_DIRECTORY` | core | Mounted report artifact directory. |
| `CORS_ALLOWED_ORIGINS` | core | Exact comma-separated browser origin allowlist. |
| `CORS_ALLOWED_METHODS` | core | Allowed CORS methods. |
| `CORS_ALLOWED_HEADERS` | core | Allowed request headers. |
| `CORS_EXPOSED_HEADERS` | core | Response headers readable by a browser. |
| `CORS_ALLOW_CREDENTIALS` | core | Whether cross-origin credentials are permitted. |
| `CORS_MAX_AGE` | core | Browser preflight cache duration in seconds. |
| `ML_GRPC_HOST` | ml | ML gRPC bind host. |
| `ML_GRPC_PORT` | ml | ML gRPC bind port. |
