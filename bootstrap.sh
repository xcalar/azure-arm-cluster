#!/bin/bash

echo "Starting bootstrap at `date`"

INSTALLER_SERVER="https://zqdkg79rbi.execute-api.us-west-2.amazonaws.com/stable/installer"
LICENSE_SERVER="https://x3xjvoyc6f.execute-api.us-west-2.amazonaws.com/production/license/api/v1.0/marketplacedeploy"
HTML="http://pub.xcalar.net/azure/dev/html-4.tar.gz"
XCALAR_ADVENTURE_DATASET="http://pub.xcalar.net/datasets/xcalarAdventure.tar.gz"
CONTAINER="customer"

# By default use the LetsEncrypt staging server so we don't trigger
# CA limits for this domain
CASTAGING="https://acme-staging.api.letsencrypt.org/directory"
CASERVER="$CASTAGING"

while getopts "a:b:c:d:e:f:g:i:n:l:u:r:p:s:t:v:w:x:y:z:" optarg; do
    case "$optarg" in
        a) SUBDOMAIN="$OPTARG";;
        b) export AWS_HOSTED_ZONE_ID="$OPTARG";;
        c) CLUSTER="$OPTARG";;
        d) DNSLABELPREFIX="$OPTARG";;
        e) export AWS_ACCESS_KEY_ID="$OPTARG";;
        f) export AWS_SECRET_ACCESS_KEY="$OPTARG";;
        g) PASSWORD="$OPTARG";;
        i) INDEX="$OPTARG";;
        n) COUNT="$OPTARG";;
        l) LICENSE="$OPTARG";;
        u) INSTALLER_URL="$OPTARG";;
        r) CASERVER="$OPTARG";;
        p) PEM_URL="$OPTARG";;
        t) CONTAINER="$OPTARG";;
        s) NFSMOUNT="$OPTARG";;
        v) ADMIN_EMAIL="$OPTARG";;
        w) ADMIN_USERNAME="$OPTARG";;
        x) ADMIN_PASSWORD="$OPTARG";;
        y) export AZURE_STORAGE_ACCOUNT="$OPTARG";;
        z) export AZURE_STORAGE_ACCESS_KEY="$OPTARG"; export AZURE_STORAGE_KEY="$OPTARG";;
        --) break;;
        *) echo >&2 "Unknown option $optarg $OPTARG";; # exit 2;;
    esac
done
shift $((OPTIND-1))

CLUSTER="${CLUSTER:-${HOSTNAME%%[0-9]*}}"
NFSMOUNT="${NFSMOUNT:-${CLUSTER}0:/srv/share}"

XLRDIR=/opt/xcalar

# Safer curl. Use IPv4, follow redirects (-L), and add some retries. We've seen curl
# try to use IPv6 on AWS, and many intermittent errors when not retrying. --location
# to follow redirects is pretty much mandatory.
safe_curl () {
    curl -4 --location --retry 20 --retry-delay 3 --retry-max-time 60 "$@"
}

# Removes an entry from fstab
clean_fstab () {
    test -n "$1" && sed -i '\@'$1'@d' /etc/fstab
}

create_swapunits () {
	cat > /lib/systemd/system/create-swapfile.service <<EOF
[Unit]
Description=Create a swapfile
RequiresMountsFor=$1

[Service]
Type=oneshot
Environment=SWAPSIZE=$2
EnvironmentFile=-/etc/default/swapfile
ExecStart=-/usr/bin/fallocate -l \$SWAPSIZE $1/swapfile
ExecStart=/usr/bin/chmod 600 $1/swapfile
ExecStart=-/usr/sbin/mkswap $1/swapfile
ExecStart=-/usr/sbin/swapon $1/swapfile
ExecStop=-/usr/sbin/swapoff $1/swapfile
ExecStop=-/usr/bin/rm -f $1/swapfile
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable create-swapfile.service
    systemctl restart create-swapfile.service
}

create_xcalarunits () {
    cat > /etc/tmpfiles.d/xcalar.conf <<EOF
d  /var/tmp/xcalar-root  0755  xcalar xcalar - -
d  $1  0755  xcalar xcalar - -
EOF
    systemctl daemon-reload
    systemctl enable systemd-tmpfiles-setup.service
    systemd-tmpfiles --create /etc/tmpfiles.d/xcalar.conf
}

# mount_device /path /dev/partition will mount the given partition to the path. If
# the partition doesn't exist it is created from the underlying device. If the
# device is already mounted somewhere else, it is unmounted. *CAREFUL* when calling
# this function, it will destroy the specified device.
mount_device () {
    test $# -ge 2 || return 1
    test -n "$1" && test -n "$2" || return 1
    local PART= MOUNT="$1" PARTIN="$2" DEV="${2%[1-9]}" LABEL="$3" FSTYPE="${4:-ext4}"
    if PART="$(set -o pipefail; findmnt -n $MOUNT | awk '{print $2}')"; then
        local OLDMOUNT="$(findmnt -n $MOUNT | awk '{print $1}')"
        if [ "$PART" != "$PARTIN" ] || [ -z "$OLDMOUNT" ]; then
            echo >&2 "Bad mount $MOUNT on device $PARTIN. Bailing." >&2
            return 1
        fi
        umount $OLDMOUNT
    fi
    # If there's already a partition table, you need to sgdisk it twice
    # because it 'fails' the first time. sgdisk aligns the partition for you
    # -n1 creates an aligned partition using the entire disk, -t1 sets the
    # partition type to 'Linux filesystem' and -c1 sets the label to 'LABEL'
    sgdisk -Zg -n1:0:0 -t1:8300 -c1:$LABEL $DEV || sgdisk -Zg -n1:0:0 -t1:8300 -c1:$LABEL $DEV
    test $? -eq 0 || return 1
    sync
    local retry=
    for retry in $(seq 5); do
        sleep 5
        if [ "$FSTYPE" = xfs ]; then
            time mkfs.xfs -f $PARTIN && break
        elif [ "$FSTYPE" = ext4 ]; then
            # Must use -F[orce] because the partition may have already existed with a valid
            # file system. sgdisk doesn't earase the partitioning information, unlike parted/fdisk.
            # lazy_itable_init=0,lazy_journal_init=0 take too long on Azure
            time mkfs.ext4 -F -m 0 -E nodiscard $PARTIN && break
        fi
    done
    test $? -eq 0 || return 1
    local UUID="$(blkid -s UUID $PARTIN -o value)"
    clean_fstab $UUID && \
    clean_fstab $PARTIN && \
    mkdir -p $MOUNT && \
    if [ "$FSTYPE" = xfs ]; then
        echo "UUID=$UUID   $MOUNT      xfs         defaults,discard,relatime,nobarrier,nofail  0   0" | tee -a /etc/fstab
    elif [ "$FSTYPE" = ext4 ]; then
        echo "UUID=$UUID   $MOUNT      ext4        defaults,discard,relatime,nobarrier,nofail  0   0" | tee -a /etc/fstab
    fi
    mount $MOUNT
}

setenforce Permissive
sed -i -e 's/^SELINUX=enforcing.*$/SELINUX=permissive/g' /etc/selinux/config

# AzureCLI (ref: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)
rpm --import https://packages.microsoft.com/keys/microsoft.asc
echo -e "[azure-cli]\nname=Azure CLI\nbaseurl=https://packages.microsoft.com/yumrepos/azure-cli\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/azure-cli.repo

yum makecache fast

#Not used > 7.3
if grep -q '7\.3' /etc/redhat-release; then
    # See https://docs.microsoft.com/en-us/azure/storage/common/storage-premium-storage#premium-storage-for-linux-vms
    rpm -e hypervkvpd || true
    yum install -y microsoft-hyper-v
fi

yum install -y nfs-utils epel-release parted gdisk curl
yum install -y jq python-pip awscli azure-cli sshpass htop tmux iperf3 vim-enhanced ansible

# For CIFS
yum install -y samba-client samba-common cifs-utils

pip install -U jinja2

test -n "$HTML" && safe_curl -sSL "$HTML" > html.tar.gz

tar -zxvf html.tar.gz

serveError() {
    errorMsg="$1"
    rectifyMsg="$2"
    cd html
    python ./render.py "$errorMsg" "$rectifyMsg"
    nohup python -m SimpleHTTPServer 80 >> /var/log/xcalarHttp.log 2>&1 &
}

# If INSTALLER_URL is provided, then we don't have to check the license
if [ -z "$INSTALLER_URL" ]; then
    retVal=`safe_curl -H "Content-Type: application/json" -X POST -d "{ \"licenseKey\": \"$LICENSE\", \"numNodes\": $COUNT, \"installerVersion\": \"latest\" }" $INSTALLER_SERVER`
    success=`echo "$retVal" | jq .success`
    if [ "$success" = "false" ]; then
        errorMsg=`echo "$retVal" | jq -r .error`
        echo 2>&1 "ERROR: $errorMsg"
        if [ "$errorMsg" = "License key not found" ]; then
            rectifyMsg="Please contact Xcalar at <a href=\"mailto:sales@xcalar.com\">sales@xcalar.com</a> for a trial license"
        else
            rectifyMsg="Please contact Xcalar support at <a href=\"mailto:support@xcalar.com\">support@xcalar.com</a>"
        fi
        serveError "$errorMsg" "$rectifyMsg"
        exit 1
    fi
    INSTALLER_URL=`echo "$retVal" | jq -r '.signedUrl'`
fi

# If on a single node instance, use the local host
# as the server
if [ -z "$NFSHOST" ] && [ "$COUNT" = 1 ]; then
    NFSMOUNT="${HOSTNAME}:/srv/share"
else
    NFSMOUNT="${CLUSTER}0:/srv/share"
fi

NFSHOST="${NFSMOUNT%%:*}"
SHARE="${NFSMOUNT##*:}"

XCE_HOME="${XCE_HOME:-/mnt/xcalar}"
XCE_CONFIG="${XCE_CONFIG:-/etc/xcalar/default.cfg}"
XCE_LICENSEDIR="${XCE_LICENSEDIR:-/etc/xcalar}"

# Download the installer as soon as we can
safe_curl -sSL "$INSTALLER_URL" > installer.sh
if [ `du installer.sh | cut -f 1` = "0" ]; then
    echo >&2 "ERROR: Error downloading installer"
    serveError "Error downloading installer"
    exit 1
fi

# Determine our CIDR by querying the metadata service
safe_curl -H Metadata:True "http://169.254.169.254/metadata/instance?api-version=2017-08-01&format=json" | jq . > metadata.json
retCode=$?
if [ "$retCode" != "0" ]; then
    echo >&2 "ERROR: Could not contact metadata service"
    serveError "Could not contact metadata service" "Please contact Xcalar support at <a href=\"mailto:support@xcalar.com\">support@xcalar.com</a>"
    exit $retCode
fi

NETWORK="$(<metadata.json jq -r '.network.interface[].ipv4.subnet[].address')"
MASK="$(<metadata.json jq -r '.network.interface[].ipv4.subnet[].prefix')"
LOCALIPV4="$(<metadata.json jq -r '.network.interface[].ipv4.ipAddress[].privateIpAddress')"
PUBLICIPV4="$(<metadata.json jq -r '.network.interface[].ipv4.ipAddress[].publicIpAddress')"
LOCATION="$(<metadata.json jq -r '.compute.location')"
VMSIZE="$(<metadata.json jq -r '.compute.vmSize')"

# On some Azure instances /mnt/resource comes premounted but not aligned properly
INSTANCESTORE=/mnt/resource
if ! test -d $INSTANCESTORE; then
    if ! RESOURCEDEV="$(set -o pipefail; findmnt -n $INSTANCESTORE | awk '{print $2}')"; then
		if test -b /dev/disk/azure/resource-part1; then
			RESOURCEDEV=$(readlink -f /dev/disk/azure/resource-part1)
		elif test -b /dev/disk/azure/resource; then
			RESOURCEDEV=$(readlink -f /dev/disk/azure/resource)1
		fi
	fi
    mount_device $INSTANCESTORE $RESOURCEDEV SSD ext4
fi

MEMSIZEMB=$(free -m | awk '/Mem:/{print $2}')
SWAPSIZEMB=$MEMSIZEMB
case "$VMSIZE" in
	Standard_E*) SWAPSIZEMB=$((MEMSIZEMB*2));;
	*)
esac
create_swapunits "$INSTANCESTORE" "${SWAPSIZEMB}m"

# Format and mount additional SSD, and prefer to use that
for DEV in /dev/sdb /dev/sdc /dev/sdd; do
    if test -b ${DEV} && ! test -b "${DEV}1"; then
        mount_device /mnt/ssd  "${DEV}1" SSD2 xfs
        LOCALSTORE=/mnt/ssd
        break
    fi
done

# Node 0 will host NFS shared storage for the cluster
if [ "$HOSTNAME" = "$NFSHOST" ]; then
    mkdir -p "${LOCALSTORE}/share" "$SHARE"
    clean_fstab "${LOCALSTORE}/share"
    echo "${LOCALSTORE}/share    $SHARE   none   bind   0 0" | tee -a /etc/fstab
    mountpoint -q $SHARE || mount $SHARE
    # Ensure NFS is running
    systemctl enable rpcbind
    systemctl enable nfs-server
    systemctl enable nfs-lock
    systemctl enable nfs-idmap
    systemctl start rpcbind
    systemctl start nfs-server
    systemctl start nfs-lock
    systemctl start nfs-idmap

    # Export the share to everyone in our CIDR block and mark it
    # as world r/w
    mkdir -p "${SHARE}/xcalar"
    chmod 0777 "${SHARE}/xcalar"
    echo "${SHARE}/xcalar      ${NETWORK}/${MASK}(rw,sync,no_root_squash,no_all_squash)" | tee /etc/exports
    systemctl restart nfs-server
    if firewall-cmd --state; then
        firewall-cmd --permanent --zone=public --add-service=nfs
        firewall-cmd --reload
    fi
fi


### Install Xcalar
if [ -f "installer.sh" ]; then
    if ! bash -x installer.sh --nostart --caddy --startonboot; then
        echo >&2 "ERROR: Failed to run installer"
        serveError "Failed to run installer" "Please contact Xcalar support at <a href=\"mailto:support@xcalar.com\">support@xcalar.com</a>"
        exit 1
    fi
    curl -sSL http://repo.xcalar.net/deps/caddy_linux_amd64_custom-0.10.3.tar.gz | tar zxf - -C ${XLRDIR}/bin caddy
    chmod 0755 $XLRDIR/bin/caddy
    chown root:root $XLRDIR/bin/caddy
    setcap cap_net_bind_service=+ep $XLRDIR/bin/caddy
fi

# Returns relative date in az compatible format
# ex: format_expiry "10 days" -> 2017-10-01T1200Z
az_format_expiry () {
    date -u -d "$1" +'%Y-%m-%dT%H:%MZ'
}

# generate an az storage account sas token given an expiry date relative from now (eg, "10 days")
# more info: az storage account generate-sas --help
# quick ref: services -> (b)lob, (f)ile ..
#            resource-types -> (s)ervice, (c)ontainer, (o)bject
#            permissions -> (a)dd, (c)create, ..
az_storage_sas () {
    az storage account generate-sas --services bfqt --resource-types sco --permissions acdlpruw --expiry $(az_format_expiry "$1") --output tsv
}

# TODO: Should store this instead of AZURE_*_KEY
export AZURE_STORAGE_SAS_TOKEN="$(az_storage_sas '90 days')"
if touch /etc/azure; then
    # Only allow access by root
    chmod 0600 /etc/azure
    echo "## Azure Blob Storage config" >> /etc/azure
    echo "AZURE_STORAGE_ACCOUNT=$AZURE_STORAGE_ACCOUNT" >> /etc/azure
    echo "AZURE_STORAGE_ACCESS_KEY=$AZURE_STORAGE_ACCESS_KEY" >> /etc/azure
    echo "AZURE_STORAGE_KEY=$AZURE_STORAGE_KEY" >> /etc/azure
    echo "AZURE_STORAGE_SAS_TOKEN=\"$AZURE_STORAGE_SAS_TOKEN\"" >> /etc/azure
    echo "export AZURE_STORAGE_ACCOUNT AZURE_STORAGE_ACCESS_KEY AZURE_STORAGE_KEY AZURE_STORAGE_SAS_TOKEN" >> /etc/azure
    if [ -r /etc/default/xcalar ]; then
        # should filter out _KEY and only keep ACCOUNT_NAME and SAS_TOKEN in
        # /etc/default/xcalar. Since this file contains secrets, remove world
        # readable bit
        chmod 0640 /etc/default/xcalar
        cat /etc/azure | tee -a /etc/default/xcalar >/dev/null
        . /etc/default/xcalar
    else
        . /etc/azure
    fi
fi

# Only have head node create the container
if [ "$INDEX" = 0 ] && [ -n "$CONTAINER" ]; then
    # Don't strictly need to pass the account name and sas token as they're in env vars, just here
    # for reference should we decide to remove the global env vars
    CONTAINER_CREATED=$(az storage container create --account-name "$AZURE_STORAGE_ACCOUNT" --sas-token "$AZURE_STORAGE_SAS_TOKEN" --name $CONTAINER --query 'created')
    if [ "$CONTAINER_CREATED" = true ]; then
        echo "Created container $CONTAINER"
    else
        echo "Failed to create container $CONTAINER"
    fi
fi

# Generate a list of all cluster members
DOMAIN="$(dnsdomainname)"
MEMBERS=()
for ii in $(seq 0 $((COUNT-1))); do
    MEMBERS+=("${CLUSTER}${ii}")
done

# Register domain
CNAME="${DNSLABELPREFIX}-${INDEX}.${LOCATION}.cloudapp.azure.com"
if [ -z "$SUBDOMAIN" ]; then
    SUBDOMAIN="${LOCATION}.cloudapp.azure.com"
fi

DEPLOYED_URL=""
XCE_DNS=""
cp -n /etc/xcalar/Caddyfile /etc/xcalar/Caddyfile.orig
if [ "$PUBLICIPV4" != "" ]; then
    if [ "$INDEX" = 0 ]; then
        XCE_DNS="${DNSLABELPREFIX}.${SUBDOMAIN}"
    fi
    if [ -z "$XCE_DNS" ]; then
        XCE_DNS="${DNSLABELPREFIX}-${INDEX}.${SUBDOMAIN}"
    fi
    #aws_route53_record "${CNAME}" "${XCE_DNS}"
    (
    echo ":443, https://${XCE_DNS}:443 {"
    tail -n+2 /etc/xcalar/Caddyfile
    echo ":80, http://${XCE_DNS} {"
    echo "  redir https://{host}{uri}"
    echo "}"
    ) | tee /etc/xcalar/Caddyfile.$$
    mv /etc/xcalar/Caddyfile.$$ /etc/xcalar/Caddyfile
    # Have to add the -agree flag or caddy asks us interactively
    sed -i -e 's/caddy -quiet/caddy -quiet -agree/g' /etc/xcalar/supervisor.conf
    if [ "$INDEX" = 0 ] && test -e "/etc/xcalar/${XCE_DNS}.key"; then
        sed -i -e "s|tls.*$|tls /etc/xcalar/${XCE_DNS}.crt /etc/xcalar/${XCE_DNS}.key|g" /etc/xcalar/Caddyfile
        DEPLOYED_URL="https://$XCE_DNS"
    else
        sed -i -e 's/tls.*$/tls self_signed/g' /etc/xcalar/Caddyfile
        DEPLOYED_URL="https://$CNAME"
    fi
else
    (
    echo ":443 {"
    tail -n+2 /etc/xcalar/Caddyfile.orig
    echo ":80 {"
    echo "  redir https://{host}{uri}"
    echo "}"
    ) | sed -e 's/tls.*$/tls self_signed/g' | tee /etc/xcalar/Caddyfile.$$
    mv /etc/xcalar/Caddyfile.$$ /etc/xcalar/Caddyfile
fi

# Custom SerDes path on local storage
XCE_XDBSERDESPATH="${INSTANCESTORE}/serdes"
# Generate /etc/xcalar/default.cfg
(
if [ $COUNT -eq 1 ]; then
    ${XLRDIR}/scripts/genConfig.sh /etc/xcalar/template.cfg - localhost
else
    ${XLRDIR}/scripts/genConfig.sh /etc/xcalar/template.cfg - "${MEMBERS[@]}"
fi
# Enable ASUP on Cloud deployments
echo Constants.SendSupportBundle=true

mkdir -m 0700 -p $XCE_XDBSERDESPATH && \
chown xcalar:xcalar $XCE_XDBSERDESPATH && \
echo Constants.XdbLocalSerDesPath=$XCE_XDBSERDESPATH
) | tee "$XCE_CONFIG"

if ! test -e "${XCE_LICENSEDIR}/XcalarLic.key"; then
    echo "$LICENSE" > "${XCE_LICENSEDIR}/XcalarLic.key"
fi

# Make Xcalar config dir writable by xcalar user for config changes via XD
chown -R xcalar:xcalar /etc/xcalar

# Set up the mount for XcalarRoot
mkdir -p "$XCE_HOME"
clean_fstab $XCE_HOME
echo "${NFSMOUNT}/xcalar   $XCE_HOME    nfs     defaults,nofail    0   0" | tee -a /etc/fstab

# Set up the mount for XcalarRoot
create_xcalarunits "$XCE_XDBSERDESPATH"
sed -r -i -e 's@^Constants.XcalarRootCompletePath=.*$@Constants.XcalarRootCompletePath='$XCE_HOME'@g' "$XCE_CONFIG"

# Wait for Node0 NFS server to fully come up. Often times the other nodes get to this point before node0 has
# even begun
until mountpoint -q "$XCE_HOME"; do
    echo >&2 "Sleeping ... waiting $XCE_HOME"
    sleep 5
    mount "$XCE_HOME"
done

# Manage a stale NFS handle
until mkdir -p "${XCE_HOME}/members"; do
    umount "$XCE_HOME"
    mount "$XCE_HOME"
    echo >&2 "Sleeping ... waiting $XCE_HOME/members"
    sleep 5
done

echo "$LOCALIPV4        $(hostname -f)  $(hostname -s)" > "${XCE_HOME}/members/${INDEX}"
while :; do
    COUNT_ONLINE=$(find "${XCE_HOME}/members/" -type f | wc -l)
    echo >&2 "Have ${COUNT_ONLINE}/${COUNT} nodes online"
    if [ $COUNT_ONLINE -eq $COUNT ]; then
        break
    fi
    echo >&2 "Sleeping ... waiting for nodes"
    sleep 5
done

# Let's retrieve the xcalar adventure datasets now
if test -n "$XCALAR_ADVENTURE_DATASET"; then
    safe_curl -sSL "$XCALAR_ADVENTURE_DATASET" > xcalarAdventure.tar.gz
    tar -zxvf xcalarAdventure.tar.gz
    mkdir -p /netstore/datasets/adventure
    mv XcalarTraining /netstore/datasets/
    mv dataPrep /netstore/datasets/adventure/
    chmod -R 755 /netstore
fi

service xcalar start

# Add in the default admin user into Xcalar
if [ ! -z "$ADMIN_USERNAME" ]; then
    mkdir -p $XCE_HOME/config
    chown -R xcalar:xcalar $XCE_HOME/config /etc/xcalar
    jsonData="{ \"defaultAdminEnabled\": true, \"username\": \"$ADMIN_USERNAME\", \"email\": \"$ADMIN_EMAIL\", \"password\": \"$ADMIN_PASSWORD\" }"
    echo "Creating default admin user $ADMIN_USERNAME ($ADMIN_EMAIL)"
    # Don't fail the deploy if this curl doesn't work
    safe_curl -H "Content-Type: application/json" -X POST -d "$jsonData" "http://127.0.0.1:12124/login/defaultAdmin/set" || true
else
    echo "ADMIN_USERNAME is not specified"
fi

if [ ! -z "$DEPLOYED_URL" ]; then
    # Inform license server about URL
    jsonData="{ \"key\": \"$LICENSE\", \"url\": \"$DEPLOYED_URL\", \"marketplaceName\": \"azure\" }"
    safe_curl -H "Content-Type: application/json" -X POST -d "$jsonData" "$LICENSE_SERVER"
fi

