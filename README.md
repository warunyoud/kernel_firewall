# kernel_firewall

This repository contains two Kernel modules custom_firewall and http_sniffer

## Running the module

Get into the directory `cd [module_name]`

Use the Makefile `make`

Install the module into the Kernel `sudo insmod [module_name].ko`

## Removing the module

To remove run `sudo rmmod [module_name].ko`

To clean run `make clean`
