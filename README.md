# Mira REST API Examples

Mira Encrypted Traffic Orchestrator (ETO) and Central Manger both have a builtin
REST API framework which allows for administrators to manage the appliance using
external applications, allowing for custom management frameworks to be developed.

The REST API is based on a OpenAPI swagger schema which can be accessed at
https://*eto-hostname*/api/swagger The WebUI provides automated documentation
based on this schema which can be accessed via “System” => “Development”, note this
tab will only be visible for users with the developer permission group.

For the REST API Getting Started Guide please visit
[Mira Support Site](https://support.mirasecurity.com)

This repository contains python examples using the following client libraries.

[Bravado library examples](python/bravado)
[Requests library examples](python/requests)
