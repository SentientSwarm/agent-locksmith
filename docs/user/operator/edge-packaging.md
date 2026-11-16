# Edge packaging: systemd units in Incus containers

`dist/edge/` packages Locksmith, and optionally Pipelock and a classifier
sidecar, as hardened systemd services, one Incus system container per
instance. You describe your deployment once in a **site file** and keep it
in your own private repository. The tools turn it into reviewable Incus
commands and inactive unit definitions. Nothing they produce starts a
container or a service, and nothing ships a credential or model weights.

The tools need Python 3.11 or later and only the standard library. The
containers need `python3`, `nft` and `findmnt`; a stock Ubuntu 24.04
container image has all three.

## 1. Write the site file

Start from [`dist/edge/site.example.toml`](../../../dist/edge/site.example.toml)
and replace every value.

```toml
[site]
state_root = "/srv/locksmith-edge"   # each instance's state volume is mounted here
require_zfs = true                   # refuse to start unless that mount is ZFS

[[instance]]
name = "edge-locksmith"
address = "10.0.4.10"                # optional fixed address on eth0
cpu = 2
memory = "2GiB"

[[instance.component]]
name = "locksmith"
user = "locksmith"
command = "/usr/local/bin/locksmithd --config /srv/locksmith-edge/locksmith/config.yaml"
environment_file = true              # load /srv/locksmith-edge/environment/locksmith.env
ingress = [{ port = 9200, from = ["10.0.1.0/24"] }]
```

Each component also takes `jit = true`, which allows writable executable
memory for runtimes that need it, such as Python with ONNX. It also takes
`env = { NAME = "value" }` for extra variables on the service command.

The loader refuses:

- unknown keys and duplicate instance or component names;
- a state root that is not a plain absolute path;
- a component running as `root` or `nobody`;
- bad CIDRs or ports;
- control characters in a command or variable.

Run any tool on the file to check it.

Pipelock is optional. Without a Pipelock instance, set `egress.mode:
external` in the Locksmith config and enforce egress in your network. See
[what you lose without Pipelock](../concepts/egress-and-inspection.md#what-you-lose-without-pipelock).
With Pipelock, run it in `strict` mode, because only `strict` enforces the
host allowlist.

## 2. Prepare the containers

```bash
python3 dist/edge/incus.py site.toml --project edge \
  --image images:ubuntu/24.04/amd64 --pool default --volume-size 64GiB > prepare.sh
less prepare.sh          # review it
sudo bash prepare.sh
```

The script:

- refuses a VM image;
- refuses a project whose `limits.containers` is below the instance count;
- refuses any instance or `<instance>-state` volume that already exists;
- creates each container **stopped**, with `boot.autostart=false`, no
  nesting, no privileged mode and the site's limits;
- creates each instance's dedicated state volume and mounts it at
  `state_root`.

Create the project and set its limits yourself first. With
`require_zfs = true`, `--pool` must be a ZFS pool, or the guard refuses to
start every component. To refuse conflicts
before generating the script, pass `--existing inventory.json` with
`{"instances": [...], "volumes": [...]}`.

## 3. Render and install the definitions

Render each instance into a directory that does not exist yet:

```bash
python3 dist/edge/render.py site.toml edge-locksmith ./render/edge-locksmith
```

The tree contains:

- `usr/local/lib/systemd/system/locksmith-edge-<component>.service`;
- `locksmith-edge-<component>-guard.service`, which runs the root guard
  before every start of its component (see step 6);
- `locksmith-edge-input.service`, which loads the ingress table;
- `etc/locksmith-edge/input.nft`, which accepts TCP on each declared port
  only from its listed CIDRs and rejects it for everyone else. Other
  protocols are not filtered;
- `etc/sysusers.d/locksmith-edge.conf`;
- `etc/locksmith-edge/components.json`;
- the root guard at `usr/local/sbin/locksmith-edge-state-check`.

It has no enabled-unit links and no receipts. Any existing output
directory is refused, so a render can never overwrite a live tree.

Boot the container. No application unit is enabled, and each one is gated
on a receipt you have not created. Copy the tree in as root, so every file
is root-owned:

```bash
sudo incus --project edge start edge-locksmith
tar -C ./render/edge-locksmith -cf - etc usr | \
  sudo incus --project edge exec edge-locksmith -- tar -xf - -C / --no-same-owner --no-overwrite-dir
sudo incus --project edge exec edge-locksmith -- sh -c 'systemd-sysusers && systemctl daemon-reload'
```

Install the service binaries the commands name, such as `locksmithd` built
with the [tested recipe](../../development/build-identity.md#build-with-the-tested-recipe).

## 4. Lay out the state volume

Inside the container, as root:

```bash
R=/srv/locksmith-edge
echo edge-locksmith > $R/.locksmith-edge-id        # must name this instance
install -d -m 0755 $R/custody
install -d -m 0700 -o locksmith -g locksmith $R/locksmith $R/locksmith/home
install -d -m 0700 $R/environment                  # only if a component sets environment_file
install -m 0600 /dev/null $R/environment/locksmith.env
```

`$R` itself, `.locksmith-edge-id`, `custody/` and `environment/` stay
root-owned and not group- or world-writable. Each component can write only
`$R/<component>` and `/run/<component>`.

Put the Locksmith config under `$R/locksmith/`. Put its sealing keys in
`locksmith.env`, through an editor or a pipe and never on a command line.
See [sealed-state recovery](sealed-state-recovery.md) for keeping those
keys recoverable.

## 5. Install a classifier model (optional)

Model weights are not shipped. `install_model.py` downloads one of the
models pinned in `dist/edge/models.toml` into an offline Hugging Face cache.
It checks every file against its pinned SHA-256 or git blob SHA-1 before
renaming the install into place.

Run it inside the inspector's container, which needs to reach
huggingface.co for this step. Create `$R/inspector` and
`$R/inspector/home` first, owned by the inspector user, as in step 4.
Then copy the tools in:

```bash
sudo incus --project edge file push -r dist/edge edge-inspector/root/
# Ungated (Apache-2.0), no token:
sudo incus --project edge exec edge-inspector -- \
  python3 /root/edge/install_model.py horizon-small --hf-home /srv/locksmith-edge/inspector/models

# Gated (Llama 4 Community License): accept the licence on Hugging Face
# first, with the account the token belongs to. -t gives the prompt a terminal.
sudo incus --project edge exec -t edge-inspector -- \
  python3 /root/edge/install_model.py promptguard2-86m --hf-home /srv/locksmith-edge/inspector/models \
  --token-prompt --accepted-by "<who accepted>"

sudo incus --project edge exec edge-inspector -- sh -c \
  'chown -R <inspector-user>: /srv/locksmith-edge/inspector/models && rm -r /root/edge'
```

- **The token stays out of argv.** It comes from `--token-prompt` (no echo)
  or `--token-file`, a file only you can read (`chmod 600`).
- **It is sent only to huggingface.co.** It goes with the first request
  and with a redirect back to huggingface.co itself. The CDN that a
  download redirects to never receives it.
- **It is never written to disk.** It is also kept out of the
  `locksmith-manifest.json` that records the repo, revision, files and who
  accepted the licence.

A 401 or 403 means the licence has not been accepted for that account.
Delete any token file afterwards.

Run the inspector with `HF_HOME` set to the same directory and
`HF_HUB_OFFLINE=1`, as the example site does, so it never fetches at
runtime.

## 6. Acknowledge custody and start

Each component requires its own `locksmith-edge-<component>-guard.service`.
That unit runs the root guard (`python3 -I`) before every start and restart
of the component, without the component's environment file, so nothing in
that file reaches root. The guard refuses, and the component does not start,
unless:

- `components.json` and `/etc/locksmith-edge` are root-owned and not
  group- or world-writable;
- the instance and component are the ones listed in that file;
- the state root is a separately mounted filesystem (and ZFS, unless
  `require_zfs = false`);
- `.locksmith-edge-id` names this instance;
- `custody/<component>.ready` exists, is root-owned, and contains
  `<instance>:<component>`.

The receipt is your statement that this component's state is in place and
that no other copy is running anywhere. Write it only after that is true:

```bash
echo edge-locksmith:locksmith > $R/custody/locksmith.ready
systemctl enable --now locksmith-edge-input.service locksmith-edge-locksmith.service
```

A refusal is logged as `locksmith-edge startup refused: <reason>` in the
guard unit's journal (`journalctl -u locksmith-edge-locksmith-guard`). Remove the receipt to stop the unit from being started
again.

## Related

- [Egress and inspection](../concepts/egress-and-inspection.md): egress
  modes, Pipelock `strict`, the classifier gap.
- [`dist/inspector/`](../../../dist/inspector/README.md): the sidecar wire
  protocol and the reference PromptGuard sidecar.
