# Ubuntu/Debian Syste, install

## PostgreSQL

[Source](https://www.postgresql.org/download/linux/ubuntu/)

```bash
apt install postgresql -y
```

## Clickhouse

[Source](https://clickhouse.com/docs/en/install#available-installation-options)

```bash
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

ARCH=$(dpkg --print-architecture)
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list
sudo apt-get update
sudo apt-get install -y clickhouse-server clickhouse-client
sudo service clickhouse-server start

clickhouse-client -c "ALTER USER default IDENTIFIED WITH sha256_password BY default"
```

## Nginx

[Source](https://nginx.org/en/linux_packages.html#Ubuntu)

```bash
sudo apt install curl gnupg2 ca-certificates lsb-release ubuntu-keyring
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
gpg --dry-run --quiet --no-keyring --import --import-options import-show /usr/share/keyrings/nginx-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/ubuntu `lsb_release -cs` nginx" \
    | sudo tee /etc/apt/sources.list.d/nginx.list
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/mainline/ubuntu `lsb_release -cs` nginx" \
    | sudo tee /etc/apt/sources.list.d/nginx.list
sudo apt update
sudo apt install nginx -y
sudo service nginx start
```

```bash
rsync nginx/nginx.comf. HOST:/etc/nginx/nginx.conf
```

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d manyevents.cloud -d www.manyevents.cloud
```

```bash
sudo apt-get install unzip -y
```

## Release

CI/CD minimal :D

```bash
wget https://github.com/aptakhin/manyevents/archive/refs/heads/main.zip
unzip main.zip
mv manyevents-main/manyevents/static/ .
rm manyevents-main
```

```bash
wget https://github.com/aptakhin/manyevents/releases/download/v0.0/manyevents
chmod +x manyevents
whet https://raw.githubusercontent.com/aptakhin/manyevents/refs/heads/main/.env.example
mv .env.example .env
# edit .env, change to postgres/postgres/postgres
set -a; source .env; set +a

sudo -u postgres psql -c "ALTER USER postgres PASSWORD '...';"

# Run migrations
./manyevents migrate

# Means ok:
# > Migration result ()

# Debug run
./manyevents
```
