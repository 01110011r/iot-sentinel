#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

enum class DeviceState { Online, Isolated, Offline };
enum class Severity { Low, Medium, High, Critical };

struct Device { int id; std::string name, ip, type; DeviceState state; int failedLogins, trafficKbps, firmwareVersion; };
struct Alert { int id, deviceId; Severity severity; std::string message, time; bool resolved; };

std::string stateName(DeviceState value) { return value == DeviceState::Online ? "ONLINE" : value == DeviceState::Isolated ? "ISOLATED" : "OFFLINE"; }
std::string severityName(Severity value) { return value == Severity::Low ? "LOW" : value == Severity::Medium ? "MEDIUM" : value == Severity::High ? "HIGH" : "CRITICAL"; }
std::string timestamp() { std::time_t raw = std::time(NULL); std::ostringstream out; out << std::put_time(std::localtime(&raw), "%Y-%m-%d %H:%M:%S"); return out.str(); }

class SecurityController {
public:
    SecurityController() : nextDeviceId_(1), nextAlertId_(1) {
        devices_.push_back(Device{nextDeviceId_++, "Main Gateway", "192.168.1.1", "gateway", DeviceState::Online, 0, 320, 3});
        devices_.push_back(Device{nextDeviceId_++, "Warehouse Cam", "192.168.1.20", "camera", DeviceState::Online, 1, 740, 2});
        devices_.push_back(Device{nextDeviceId_++, "Door Sensor", "192.168.1.31", "sensor", DeviceState::Online, 0, 15, 1});
    }
    void dashboard() const {
        int online = 0, isolated = 0, open = 0;
        for (std::vector<Device>::const_iterator it = devices_.begin(); it != devices_.end(); ++it) { if (it->state == DeviceState::Online) ++online; if (it->state == DeviceState::Isolated) ++isolated; }
        for (std::vector<Alert>::const_iterator it = alerts_.begin(); it != alerts_.end(); ++it) if (!it->resolved) ++open;
        std::cout << "\n========== NETWORK SECURITY DASHBOARD ==========\nRegistered devices : " << devices_.size() << "\nOnline devices     : " << online << "\nIsolated devices   : " << isolated << "\nOpen alerts        : " << open << "\nPolicy: traffic <= 5000 Kbps, failed logins <= 5, firmware >= 2\n";
    }
    void showDevices() const {
        std::cout << "\n--- IoT DEVICE INVENTORY ---\n" << std::left << std::setw(4) << "ID" << std::setw(18) << "NAME" << std::setw(16) << "IP" << std::setw(12) << "TYPE" << std::setw(12) << "STATE" << "FW\n";
        for (std::vector<Device>::const_iterator it = devices_.begin(); it != devices_.end(); ++it) std::cout << std::left << std::setw(4) << it->id << std::setw(18) << it->name.substr(0,17) << std::setw(16) << it->ip << std::setw(12) << it->type.substr(0,11) << std::setw(12) << stateName(it->state) << it->firmwareVersion << "\n";
    }
    void addDevice() {
        Device d; d.id = nextDeviceId_++; d.state = DeviceState::Online; d.failedLogins = d.trafficKbps = 0;
        std::cout << "Device name: "; std::getline(std::cin, d.name); std::cout << "IP address: "; std::getline(std::cin, d.ip); std::cout << "Device type: "; std::getline(std::cin, d.type); std::cout << "Firmware version (number): "; if (!(std::cin >> d.firmwareVersion)) { clearInput(); d.firmwareVersion = 1; } clearInput(); devices_.push_back(d); std::cout << "Device registered with ID " << d.id << ".\n";
    }
    void ingestTelemetry() {
        int id, traffic, failures; std::cout << "Device ID: "; if (!(std::cin >> id)) { clearInput(); return; } Device *d = findDevice(id); if (!d) { std::cout << "Device not found.\n"; clearInput(); return; } if (d->state == DeviceState::Isolated) { std::cout << "Telemetry rejected: device is isolated.\n"; clearInput(); return; }
        std::cout << "Traffic (Kbps): "; if (!(std::cin >> traffic)) { clearInput(); return; } std::cout << "Failed login attempts: "; if (!(std::cin >> failures)) { clearInput(); return; } clearInput(); d->trafficKbps = traffic; d->failedLogins = failures; evaluate(*d); std::cout << "Telemetry processed.\n";
    }
    void showAlerts() const { if (alerts_.empty()) { std::cout << "No security alerts.\n"; return; } std::cout << "\n--- SECURITY ALERTS ---\n"; for (std::vector<Alert>::const_iterator it = alerts_.begin(); it != alerts_.end(); ++it) std::cout << "#" << it->id << " [" << severityName(it->severity) << "] " << it->time << " | Device " << it->deviceId << " | " << it->message << " | " << (it->resolved ? "RESOLVED" : "OPEN") << "\n"; }
    void isolateDevice() { int id; std::cout << "Device ID to isolate: "; if (!(std::cin >> id)) { clearInput(); return; } clearInput(); Device *d = findDevice(id); if (!d) { std::cout << "Device not found.\n"; return; } d->state = DeviceState::Isolated; addAlert(id, Severity::High, "Device isolated by security controller"); std::cout << d->name << " has been isolated from the network.\n"; }
    void resolveAlert() { int id; std::cout << "Alert ID to resolve: "; if (!(std::cin >> id)) { clearInput(); return; } clearInput(); for (std::vector<Alert>::iterator it = alerts_.begin(); it != alerts_.end(); ++it) if (it->id == id) { it->resolved = true; std::cout << "Alert resolved.\n"; return; } std::cout << "Alert not found.\n"; }
private:
    std::vector<Device> devices_; std::vector<Alert> alerts_; int nextDeviceId_, nextAlertId_;
    Device *findDevice(int id) { for (std::vector<Device>::iterator it = devices_.begin(); it != devices_.end(); ++it) if (it->id == id) return &*it; return NULL; }
    void addAlert(int deviceId, Severity severity, const std::string &message) { alerts_.push_back(Alert{nextAlertId_++, deviceId, severity, message, timestamp(), false}); }
    void evaluate(Device &d) { if (d.failedLogins > 5) addAlert(d.id, Severity::High, "Brute-force login activity detected"); if (d.trafficKbps > 5000) addAlert(d.id, Severity::Critical, "Abnormally high network traffic detected"); if (d.firmwareVersion < 2) addAlert(d.id, Severity::Medium, "Outdated firmware requires update"); }
    void clearInput() { std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }
};

int main() {
    SecurityController controller; int choice = -1; std::cout << "IoT Network Security Monitoring and Control System\n";
    while (choice != 0) { std::cout << "\n1. Dashboard\n2. List devices\n3. Register device\n4. Ingest telemetry\n5. View alerts\n6. Isolate device\n7. Resolve alert\n0. Exit\nChoice: "; if (!(std::cin >> choice)) { std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); continue; } std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); switch (choice) { case 1: controller.dashboard(); break; case 2: controller.showDevices(); break; case 3: controller.addDevice(); break; case 4: controller.ingestTelemetry(); break; case 5: controller.showAlerts(); break; case 6: controller.isolateDevice(); break; case 7: controller.resolveAlert(); break; case 0: std::cout << "System stopped.\n"; break; default: std::cout << "Invalid choice.\n"; } }
    return 0;
}
