# Matrix Invite Portal

Standalone Ansible role for the Matrix Invite Portal, a closed-registration onboarding portal for Matrix homeservers.

This repository is intended to be consumed as an external role by the main playbook, where it is installed as `galaxy/matrix-invite-portal`.

## Usage

In the main playbook, install roles with:

```sh
just roles
```

The playbook's `requirements.yml` installs this role from:

```yaml
- src: git+https://github.com/microchipster/matrix-invite-portal.git
  version: main
  name: matrix-invite-portal
```

You can also install it directly with `ansible-galaxy`:

```sh
ansible-galaxy role install git+https://github.com/microchipster/matrix-invite-portal.git -p roles/galaxy/ --force
```

## Build source pinning

The role builds its Docker image from this repository by default.

- `matrix_invite_portal_container_image_self_build: true`
- `matrix_invite_portal_container_image_self_build_repo_version: main`

If you need to pin the build to a tag, branch, or commit SHA, override `matrix_invite_portal_container_image_self_build_repo_version`.

## Key variables

The role is opt-in and expects a few explicit values in the consuming playbook:

- `matrix_invite_portal_enabled`
- `matrix_invite_portal_admin_token`
- `matrix_synapse_registration_shared_secret`
- `matrix_invite_portal_synapse_admin_access_token` for password reset flows that need Synapse admin API access

Refer to `defaults/main.yml` for the full list of supported variables.

## Repository layout

- `tasks/` contains the Ansible install and uninstall logic.
- `templates/` contains systemd and environment templates used by the playbook.
- `src/` contains the Rust application for the invite portal.
- `assets/` contains bundled UI assets used by the application.
