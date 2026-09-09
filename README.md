# IoT Network Security Monitor

A C11 console prototype for monitoring IoT devices and responding to basic network-security events. It simulates an IoT security controller that maintains a device inventory, receives telemetry, detects policy violations, and lets an operator isolate suspicious devices.

## Features

- Register and view IoT devices
- View a network-security dashboard
- Ingest device telemetry (traffic and failed login attempts)
- Detect brute-force login activity
- Detect abnormal network traffic
- Flag outdated firmware
- View and resolve security alerts
- Isolate a device from the network

## Security policies

| Check | Threshold | Alert severity |
| --- | --- | --- |
| Failed logins | More than 5 attempts | High |
| Network traffic | More than 5,000 Kbps | Critical |
| Firmware version | Below version 2 | Medium |

## Requirements

- A C11-compatible compiler, such as GCC or Clang
- CMake is optional

## Build and run

Using a C compiler:

```bash
cc -std=c11 -Wall -Wextra -pedantic main.c -o iot-sentinel
./iot-sentinel
```

Using CMake:

```bash
cmake -S . -B build
cmake --build build
./build/iot
```

## Menu

When the program starts, choose one of the following actions:

1. View the security dashboard.
2. List registered devices.
3. Register a device.
4. Submit device telemetry for evaluation.
5. View alerts.
6. Isolate a device.
7. Resolve an alert.
0. Exit the application.

## Example test case

To trigger alerts, select **Ingest telemetry** and submit a traffic value above `5000` and failed login attempts above `5`. The system creates high/critical alerts; you can then isolate the affected device from the menu.

## Current scope

This is an educational, in-memory simulation implemented in C. A production system would additionally need authenticated APIs, encrypted telemetry transport (for example, MQTT over TLS), persistent storage, role-based access control, audit logging, and integrations with real IoT gateways and SIEM tools.

## License

No license has been selected yet.
