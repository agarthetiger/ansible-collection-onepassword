# 1Password Collection for Ansible

This collection contains a single inventory plugin to use [1Password](https://1password.com/) as a dynamic inventory source.

## Installation and Usage

Installing the Collection from Ansible Galaxy

Before using this collection, you need to install it with the Ansible Galaxy CLI:

```
ansible-galaxy collection install agarthetiger.onepassword
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: agarthetiger.onepassword
    version: 0.1.0
```

Currently (Ansible v2.9.x) there is no automatic way in which Ansible knows about installed inventory plugins from Ansible Collections. Therefore it is necessary to reference the full path to the inventory folder in ansible.cfg under the `inventory_plugins` key in the `defaults` section. 

Create a file called ansible.cfg in the same folder as you are running ansible from and add the following content. 

```ini
[defaults]
inventory_plugins=~/.ansible/collections/ansible_collections/agarthetiger/onepassword/plugins/inventory
```

To use this plugin as an inventory source you must already have the 1Password [op] CLI tool installed on the machine you are running Ansible from. Follow the [installation instructions](https://support.1password.com/command-line-getting-started/) provided by 1password. 

It is highly recommended that you create a 1Password user for use with Ansible, create a Vault which contains only your inventory and grant that user account access to this Vault only.

While you can pass either just the user password or the full gamut of 1Password credentials, keys and subdomains to this plugin my recommendation is you do not. If you do, ensure these credentials are provided in a secure manner, such using Ansible Vault, and definitely not in plain text in the inventory yaml configuration file. You have been warned. 

## 1Password inventory structure

This plugin will only search for "Server" items in the Vaults the credentials grant access to. The Server items must have a field called `IP` in the top section. Each server added to the inventory can optionally be added to a single group. Add a field in the top section called `Group` with the name of the group to add the server to. 
