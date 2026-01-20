#!/usr/bin/env python3
"""
Quick fix script to update device identifications in the database
based on MAC address prefixes.
"""
import sqlite3
from datetime import datetime

# MAC OUI prefixes for device identification (must match network_scanner.py)
MAC_PREFIXES = {
    # Smart Home Devices
    "00:17:88": ("Philips", "smart_bulb"),
    "18:B4:30": ("Nest", "thermostat"),
    "44:07:0B": ("Google", "smart_speaker"),
    "F0:27:2D": ("Amazon", "alexa"),
    "AC:CC:8E": ("Roku", "streaming"),
    "D8:6C:63": ("Samsung", "smart_tv"),

    # TP-Link Devices
    "50:C7:BF": ("TP-Link", "smart_plug"),
    "5C:A6:E6": ("TP-Link", "camera"),
    "B4:E6:2D": ("TP-Link", "router"),
    "E4:C3:2A": ("TP-Link", "router"),

    # Cameras
    "2C:AA:8E": ("Wyze", "camera"),

    # Mobile Devices
    "72:E5:DC": ("Vivo", "mobile"),

    # Network Adapters
    "00:E0:4C": ("Realtek", "network_adapter"),
    "50:5A:65": ("AzureWave", "network_adapter"),
    "9C:29:76": ("Intel", "network_adapter"),

    # ESP32 / Espressif MAC OUI prefixes
    "24:0A:C4": ("Espressif", "esp32_cam"),
    "30:AE:A4": ("Espressif", "esp32_cam"),
    "3C:71:BF": ("Espressif", "esp32_cam"),
    "7C:9E:BD": ("Espressif", "esp32_cam"),
    "94:B9:7E": ("Espressif", "esp32_cam"),
    "A4:CF:12": ("Espressif", "esp32_cam"),
    "B4:E6:2E": ("Espressif", "esp32_cam"),
    "C4:D8:D5": ("Espressif", "esp32_cam"),
    "CC:50:E3": ("Espressif", "esp32_cam"),
    "DC:4F:22": ("Espressif", "esp32_cam"),
    "EC:FA:BC": ("Espressif", "esp32_cam"),
    "F4:CF:A2": ("Espressif", "esp32_cam"),
}

def identify_device(mac: str):
    """Identify device from MAC address."""
    if not mac or mac == "unknown":
        return None, None

    mac_prefix = mac[:8].upper()
    if mac_prefix in MAC_PREFIXES:
        return MAC_PREFIXES[mac_prefix]
    return None, None

def main():
    db_path = "data/rakshak.db"

    print("=" * 70)
    print("RAKSHAK Device Identification Fixer")
    print("=" * 70)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get all devices
    cursor.execute("SELECT ip, mac, hostname, manufacturer, device_type FROM devices ORDER BY ip")
    devices = cursor.fetchall()

    print(f"\nFound {len(devices)} devices in database\n")

    updated_count = 0

    for device in devices:
        ip = device['ip']
        mac = device['mac']
        hostname = device['hostname']
        old_manufacturer = device['manufacturer']
        old_device_type = device['device_type']

        # Try to identify
        manufacturer, device_type = identify_device(mac)

        if manufacturer and device_type:
            if old_manufacturer != manufacturer or old_device_type != device_type:
                print(f"✓ {ip:15} | {mac:17} | {hostname:20}")
                print(f"  OLD: {old_manufacturer:15} / {old_device_type}")
                print(f"  NEW: {manufacturer:15} / {device_type}")
                print()

                # Update database
                cursor.execute("""
                    UPDATE devices
                    SET manufacturer = ?, device_type = ?
                    WHERE ip = ?
                """, (manufacturer, device_type, ip))

                updated_count += 1
            else:
                print(f"- {ip:15} | {mac:17} | {hostname:20} - Already correct")
        else:
            print(f"✗ {ip:15} | {mac:17} | {hostname:20} - No MAC prefix match")

    conn.commit()
    conn.close()

    print("\n" + "=" * 70)
    print(f"Updated {updated_count} device(s)")
    print("=" * 70)
    print("\nPlease restart the RAKSHAK application for changes to take effect.")

if __name__ == "__main__":
    main()
