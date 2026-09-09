# Azure VM backend deployment

This deployment runs only the Go Core API and Python ML worker on an Azure Linux VM. The Next.js frontend remains on Vercel at `https://alchemist160.vercel.app/`; it is not built or run on the VM.

## 1. Create the Azure VM

1. Sign in at [Azure Portal](https://portal.azure.com/), search for **Virtual machines**, then select **Create** > **Azure virtual machine**.
2. Choose a resource group and region. Select **Ubuntu Server 24.04 LTS** and a size with at least 2 vCPUs and 4 GiB RAM.
3. Under **Administrator account**, select **SSH public key**, use a username such as `azureuser`, choose **Generate new key pair**, and download the `.pem` file when prompted. Azure will not offer the same private key for download again.
4. Under **Inbound port rules**, allow SSH (22) and add a custom TCP rule for port **8080**. After creation, open **Networking** and restrict SSH's source to your public IP. Do not open ports 50051 or 50052.
5. Open the VM Overview page, copy its public IP, and assign it a **Static** allocation.

Microsoft's current [Linux VM portal quickstart](https://learn.microsoft.com/en-us/azure/azure-linux/quick-create-vm-portal) and [SSH key guide](https://learn.microsoft.com/en-us/azure/virtual-machines/ssh-keys-portal) cover the portal flow.

## 2. SSH using the downloaded `.pem`

On macOS or Linux, run locally (replace the file path and IP):

```bash
chmod 400 ~/Downloads/alchemist-vm.pem
ssh -i ~/Downloads/alchemist-vm.pem azureuser@20.2.67.170
```

On Windows PowerShell:

```powershell
ssh -i "$HOME\Downloads\alchemist-vm.pem" azureuser@20.2.67.170
```

## 3. Install Docker once

Run this on the VM:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
exit
```

Reconnect with SSH, then confirm `docker --version` and `docker compose version` work.

## 4. Clone the public repository

Because the repository is public, no GitHub SSH key, deploy key, personal
access token, or GitHub login is required on the VM. The Azure `.pem` key is
only for SSH access to the VM; it is unrelated to GitHub.

Clone only deployment files instead of cloning then deleting `frontend/`:

```bash
git clone --filter=blob:none --sparse https://github.com/naman9271/SIH26160-Alchemist.git alchemist
cd alchemist
git sparse-checkout set backend deploy
```

Root deployment files such as `.env.example`, `compose.yaml`, and `Makefile`
remain included automatically. This is safer and uses less space. If you use a
full clone anyway, delete `frontend/` only after `cd alchemist`; sparse checkout
is preferred and needs no deletion.

## 5. Configure and start backend containers

```bash
cp .env.example .env
nano .env
```

Keep `CORS_ALLOWED_ORIGINS=https://alchemist160.vercel.app` unless another frontend origin is required. Then start and verify:

```bash
make up
make status
docker compose logs --tail=100 backend ml
curl --fail http://20.2.67.170:8080/health
```

The health response must contain `"ready": true`. Only Core's HTTP API is public on port 8080; the ML gRPC port remains private.

## 6. Configure Vercel

In the Vercel frontend project, open **Settings** > **Environment Variables**, add this server-only value for Production (and Preview if desired), then redeploy:

```text
CORE_HTTP_URL=http://20.2.67.170:8080
```

Do **not** set `NEXT_PUBLIC_CORE_HTTP_URL` in Vercel for this simple HTTP setup. The frontend keeps browser traffic on its HTTPS Vercel origin and Vercel forwards API requests server-to-server to the VM. The backend CORS configuration allows only the Vercel frontend origin.

Because the browser is not calling the API directly, this simple deployment does not need a Caddyfile, domain, or TLS certificate. If you later need browser-direct API calls or large uploads that bypass Vercel, put an HTTPS reverse proxy such as Caddy, Azure Front Door, or Application Gateway in front of the VM first.

## Routine commands

```bash
cd ~/alchemist
git pull --ff-only
make up
make status
docker compose logs --follow backend
```

`make down` stops containers but keeps generated reports in Docker's named volume. Do not use `docker compose down --volumes` unless you intentionally want to delete reports.
