#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_DEVICES 100
#define MAX_ALERTS 500
#define NAME_SIZE 64
#define IP_SIZE 40
#define TYPE_SIZE 32
#define MESSAGE_SIZE 128
#define TIMESTAMP_SIZE 20

typedef enum { DEVICE_ONLINE, DEVICE_ISOLATED, DEVICE_OFFLINE } DeviceState;

typedef enum {
  SEVERITY_LOW,
  SEVERITY_MEDIUM,
  SEVERITY_HIGH,
  SEVERITY_CRITICAL
} Severity;

typedef struct {
  int id;
  char name[NAME_SIZE];
  char ip[IP_SIZE];
  char type[TYPE_SIZE];
  DeviceState state;
  int failed_logins;
  int traffic_kbps;
  int firmware_version;
} Device;

typedef struct {
  int id;
  int device_id;
  Severity severity;
  char message[MESSAGE_SIZE];
  char timestamp[TIMESTAMP_SIZE];
  int resolved;
} Alert;

typedef struct {
  Device devices[MAX_DEVICES];
  size_t device_count;
  Alert alerts[MAX_ALERTS];
  size_t alert_count;
  int next_device_id;
  int next_alert_id;
} SecurityController;

static const char *state_name(DeviceState state) {
  switch (state) {
  case DEVICE_ONLINE:
    return "ONLINE";
  case DEVICE_ISOLATED:
    return "ISOLATED";
  default:
    return "OFFLINE";
  }
}

static const char *severity_name(Severity severity) {
  switch (severity) {
  case SEVERITY_LOW:
    return "LOW";
  case SEVERITY_MEDIUM:
    return "MEDIUM";
  case SEVERITY_HIGH:
    return "HIGH";
  default:
    return "CRITICAL";
  }
}

static void read_line(const char *prompt, char *buffer, size_t size) {
  int ch;

  printf("%s", prompt);
  if (fgets(buffer, (int)size, stdin) == NULL) {
    if (feof(stdin)) {
      printf("\n");
      exit(0);
    }
    buffer[0] = '\0';
    return;
  }

  if (strchr(buffer, '\n') == NULL) {
    while ((ch = getchar()) != '\n' && ch != EOF) {
    }
  } else {
    buffer[strcspn(buffer, "\n")] = '\0';
  }
}

static int read_int(const char *prompt, int *value) {
  char line[64];
  char extra;

  read_line(prompt, line, sizeof(line));
  return sscanf(line, " %d %c", value, &extra) == 1;
}

static void current_timestamp(char *buffer, size_t size) {
  time_t now = time(NULL);
  struct tm *local = localtime(&now);

  if (local == NULL ||
      strftime(buffer, size, "%Y-%m-%d %H:%M:%S", local) == 0) {
    snprintf(buffer, size, "unknown");
  }
}

static Device *find_device(SecurityController *controller, int id) {
  size_t i;

  for (i = 0; i < controller->device_count; ++i) {
    if (controller->devices[i].id == id) {
      return &controller->devices[i];
    }
  }
  return NULL;
}

static void add_alert(SecurityController *controller, int device_id,
                      Severity severity, const char *message) {
  Alert *alert;

  if (controller->alert_count == MAX_ALERTS) {
    printf("Alert capacity reached; event was not recorded.\n");
    return;
  }

  alert = &controller->alerts[controller->alert_count++];
  alert->id = controller->next_alert_id++;
  alert->device_id = device_id;
  alert->severity = severity;
  snprintf(alert->message, sizeof(alert->message), "%s", message);
  current_timestamp(alert->timestamp, sizeof(alert->timestamp));
  alert->resolved = 0;
}

static void evaluate_device(SecurityController *controller, Device *device) {
  if (device->failed_logins > 5) {
    add_alert(controller, device->id, SEVERITY_HIGH,
              "Brute-force login activity detected");
  }
  if (device->traffic_kbps > 5000) {
    add_alert(controller, device->id, SEVERITY_CRITICAL,
              "Abnormally high network traffic detected");
  }
  if (device->firmware_version < 2) {
    add_alert(controller, device->id, SEVERITY_MEDIUM,
              "Outdated firmware requires update");
  }
}

static void initialize_controller(SecurityController *controller) {
  Device initial_devices[] = {
      {0, "Main Gateway", "192.168.1.1", "gateway", DEVICE_ONLINE, 0, 320, 3},
      {0, "Warehouse Cam", "192.168.1.20", "camera", DEVICE_ONLINE, 1, 740, 2},
      {0, "Door Sensor", "192.168.1.31", "sensor", DEVICE_ONLINE, 0, 15, 1}};
  size_t i;

  memset(controller, 0, sizeof(*controller));
  controller->next_device_id = 1;
  controller->next_alert_id = 1;
  for (i = 0; i < sizeof(initial_devices) / sizeof(initial_devices[0]); ++i) {
    initial_devices[i].id = controller->next_device_id++;
    controller->devices[controller->device_count++] = initial_devices[i];
  }
}

static void show_dashboard(const SecurityController *controller) {
  size_t i;
  int online = 0;
  int isolated = 0;
  int open_alerts = 0;

  for (i = 0; i < controller->device_count; ++i) {
    if (controller->devices[i].state == DEVICE_ONLINE) {
      ++online;
    } else if (controller->devices[i].state == DEVICE_ISOLATED) {
      ++isolated;
    }
  }
  for (i = 0; i < controller->alert_count; ++i) {
    if (!controller->alerts[i].resolved) {
      ++open_alerts;
    }
  }

  printf("\n========== NETWORK SECURITY DASHBOARD ==========\n"
         "Registered devices : %zu\n"
         "Online devices     : %d\n"
         "Isolated devices   : %d\n"
         "Open alerts        : %d\n"
         "Policy: traffic <= 5000 Kbps, failed logins <= 5, firmware >= 2\n",
         controller->device_count, online, isolated, open_alerts);
}

static void show_devices(const SecurityController *controller) {
  size_t i;

  printf("\n--- IoT DEVICE INVENTORY ---\n"
         "%-4s%-18s%-16s%-12s%-12s%s\n",
         "ID", "NAME", "IP", "TYPE", "STATE", "FW");
  for (i = 0; i < controller->device_count; ++i) {
    const Device *device = &controller->devices[i];
    printf("%-4d%-18.17s%-16s%-12.11s%-12s%d\n", device->id, device->name,
           device->ip, device->type, state_name(device->state),
           device->firmware_version);
  }
}

static void add_device(SecurityController *controller) {
  Device device;
  int firmware;

  if (controller->device_count == MAX_DEVICES) {
    printf("Device capacity reached.\n");
    return;
  }

  memset(&device, 0, sizeof(device));
  device.id = controller->next_device_id++;
  device.state = DEVICE_ONLINE;
  read_line("Device name: ", device.name, sizeof(device.name));
  read_line("IP address: ", device.ip, sizeof(device.ip));
  read_line("Device type: ", device.type, sizeof(device.type));
  if (!read_int("Firmware version (number): ", &firmware)) {
    firmware = 1;
  }
  device.firmware_version = firmware;
  controller->devices[controller->device_count++] = device;
  printf("Device registered with ID %d.\n", device.id);
}

static void ingest_telemetry(SecurityController *controller) {
  Device *device;
  int id;
  int traffic;
  int failures;

  if (!read_int("Device ID: ", &id)) {
    return;
  }
  device = find_device(controller, id);
  if (device == NULL) {
    printf("Device not found.\n");
    return;
  }
  if (device->state == DEVICE_ISOLATED) {
    printf("Telemetry rejected: device is isolated.\n");
    return;
  }
  if (!read_int("Traffic (Kbps): ", &traffic) ||
      !read_int("Failed login attempts: ", &failures)) {
    return;
  }

  device->traffic_kbps = traffic;
  device->failed_logins = failures;
  evaluate_device(controller, device);
  printf("Telemetry processed.\n");
}

static void show_alerts(const SecurityController *controller) {
  size_t i;

  if (controller->alert_count == 0) {
    printf("No security alerts.\n");
    return;
  }

  printf("\n--- SECURITY ALERTS ---\n");
  for (i = 0; i < controller->alert_count; ++i) {
    const Alert *alert = &controller->alerts[i];
    printf("#%d [%s] %s | Device %d | %s | %s\n", alert->id,
           severity_name(alert->severity), alert->timestamp, alert->device_id,
           alert->message, alert->resolved ? "RESOLVED" : "OPEN");
  }
}

static void isolate_device(SecurityController *controller) {
  Device *device;
  int id;

  if (!read_int("Device ID to isolate: ", &id)) {
    return;
  }
  device = find_device(controller, id);
  if (device == NULL) {
    printf("Device not found.\n");
    return;
  }

  device->state = DEVICE_ISOLATED;
  add_alert(controller, id, SEVERITY_HIGH,
            "Device isolated by security controller");
  printf("%s has been isolated from the network.\n", device->name);
}

static void resolve_alert(SecurityController *controller) {
  size_t i;
  int id;

  if (!read_int("Alert ID to resolve: ", &id)) {
    return;
  }
  for (i = 0; i < controller->alert_count; ++i) {
    if (controller->alerts[i].id == id) {
      controller->alerts[i].resolved = 1;
      printf("Alert resolved.\n");
      return;
    }
  }
  printf("Alert not found.\n");
}

int main(void) {
  SecurityController controller;
  int choice = -1;

  initialize_controller(&controller);
  printf("IoT Network Security Monitoring and Control System\n");
  while (choice != 0) {
    printf("\n1. Dashboard\n"
           "2. List devices\n"
           "3. Register device\n"
           "4. Ingest telemetry\n"
           "5. View alerts\n"
           "6. Isolate device\n"
           "7. Resolve alert\n"
           "0. Exit\n");
    if (!read_int("Choice: ", &choice)) {
      continue;
    }

    switch (choice) {
    case 1:
      show_dashboard(&controller);
      break;
    case 2:
      show_devices(&controller);
      break;
    case 3:
      add_device(&controller);
      break;
    case 4:
      ingest_telemetry(&controller);
      break;
    case 5:
      show_alerts(&controller);
      break;
    case 6:
      isolate_device(&controller);
      break;
    case 7:
      resolve_alert(&controller);
      break;
    case 0:
      printf("System stopped.\n");
      break;
    default:
      printf("Invalid choice.\n");
      break;
    }
  }
  return 0;
}
