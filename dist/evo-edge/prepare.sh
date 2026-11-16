#!/usr/bin/env bash
# Run on evo-x2-1 as root. Creates STOPPED containers only; no launch/exec.
set -euo pipefail
if [[ ${EUID} != 0 || $# != 1 ]]; then
    echo 'usage: sudo bash prepare.sh <container-image-or-alias>' >&2
    exit 2
fi
image=$1
image_info=$(incus image info "$image")
if [[ $image_info != *$'\nType: container\n'* || $image_info != *$'\nArchitecture: x86_64\n'* ]]; then
    echo 'an AMD64 container image is required; refuse a VM/other architecture' >&2
    exit 1
fi
if [[ $(incus project get edge limits.containers) != 3 || $(incus project get edge limits.memory) != 6GiB ]]; then
    echo 'unexpected edge project budget; refuse to alter it' >&2
    exit 1
fi
for entry in edge-locksmith:10:2GiB edge-pipelock:11:1GiB edge-brokers:12:3GiB; do
    IFS=: read -r name suffix memory <<< "$entry"
    if incus --project edge info "$name" >/dev/null 2>&1; then
        echo "instance $name already exists; inspect partial preparation manually" >&2
        exit 1
    fi
    if incus storage volume show zfs "$name-state" --project edge >/dev/null 2>&1; then
        echo "volume $name-state already exists; refuse to adopt custody state" >&2
        exit 1
    fi
done
for entry in edge-locksmith:10:2GiB edge-pipelock:11:1GiB edge-brokers:12:3GiB; do
    IFS=: read -r name suffix memory <<< "$entry"
    incus --project edge init "$image" "$name" \
        -c boot.autostart=false -c limits.memory="$memory" \
        -c user.edge.migration=phase5-inactive -d root,size=12GiB
    incus --project edge config device override "$name" eth0 "ipv4.address=10.250.4.$suffix"
    incus storage volume create zfs "$name-state" --project edge size=64GiB
    incus --project edge config device add "$name" custody disk \
        pool=zfs source="$name-state" path=/srv/edge-state
done
incus --project edge list --format csv -c ns4
echo 'Prepared stopped containers. No workloads, credentials or custody receipts installed.'
