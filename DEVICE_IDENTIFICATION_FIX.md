# Device Identification Fix - Summary

## Issues Found and Fixed

### 1. **MAC Prefix Case Sensitivity Issue** ✅ FIXED
**Problem:** The `_identify_device()` method converts MAC prefixes to uppercase (`device.mac[:8].upper()`), but some MAC prefixes in the dictionary were in lowercase, causing lookup failures.

**Solution:** Updated all MAC prefixes in `MAC_PREFIXES` dictionary to uppercase format in `core/network_scanner.py` (lines 105-144).

### 2. **Devices Loaded from Database Not Re-Identified** ✅ FIXED
**Problem:** When devices are loaded from the database on startup (`_load_devices_from_db()`), they retain their old "unknown" manufacturer/device_type values and are never re-identified.

**Solution:** Added call to `_identify_device()` when loading devices from database (line 571-572 in `network_scanner.py`).

### 3. **Added Debug Logging** ✅ ADDED
**Added:** Comprehensive debug logging in `_identify_device()` method to track:
- MAC address and extracted prefix
- Successful identifications
- Failed lookups

## MAC Prefixes Added

The following device MAC prefixes have been added:

| MAC Prefix | Manufacturer | Device Type | Matches Device |
|------------|--------------|-------------|----------------|
| `00:E0:4C` | Realtek | network_adapter | DEV-0001 (pavan-Nitro) |
| `72:E5:DC` | Vivo | mobile | DEV-0002 (V2246) |
| `5C:A6:E6` | TP-Link | camera | DEV-0005 (C100_6A5918) |
| `E4:C3:2A` | TP-Link | router | DEV-0006 (TL-WR841N) |
| `9C:29:76` | Intel | network_adapter | DEV-0008 |
| `C4:D8:D5` | Espressif | esp32_cam | DEV-0010 (ESP32 Camera) ⭐ |
| `94:B9:7E` | Espressif | esp32_cam | DEV-0007 |
| `50:5A:65` | AzureWave | network_adapter | DEV-0011 |

## Files Modified

1. **`core/network_scanner.py`**:
   - Lines 105-144: Updated `MAC_PREFIXES` dictionary with proper casing
   - Lines 571-572: Added re-identification for devices loaded from database
   - Lines 985-992: Added debug logging to `_identify_device()` method

## How to Apply the Fix

### Step 1: Restart the Application
```bash
# Stop the current instance (Ctrl+C if running in foreground)
# Or kill the process
pkill -f "python.*main.py"

# Start fresh
./start_monitoring.sh
```

### Step 2: Wait for Device Discovery
The application will:
1. Load devices from database and re-identify them using updated MAC prefixes
2. Discover active devices via DHCP/passive methods
3. Identify them using the updated MAC_PREFIXES dictionary
4. Save updated information to database

### Step 3: Verify the Fix
Check the API to confirm devices are properly identified:
```bash
curl http://localhost:5000/api/devices | jq '.data[] | {id, mac, manufacturer, device_type}'
```

Expected results:
```json
{
  "id": "DEV-0001",
  "mac": "00:e0:4c:68:00:e5",
  "manufacturer": "Realtek",
  "device_type": "network_adapter"
}
{
  "id": "DEV-0010",
  "mac": "c4:d8:d5:03:8e:7f",
  "manufacturer": "Espressif",
  "device_type": "esp32_cam"
}
...
```

### Step 4: Check Debug Logs
Monitor the logs for identification messages:
```bash
tail -f data/logs/rakshak_*.log | grep -E "Identifying device|Device identified|No match found"
```

You should see messages like:
```
Identifying device: MAC=c4:d8:d5:03:8e:7f, prefix=C4:D8:D5
Device identified: 10.42.0.134 (c4:d8:d5:03:8e:7f) -> Espressif / esp32_cam
```

## Additional Issues to Address

### Enrollment Status Issue
**Observation:** New devices show `enrollment_status: "unknown"` instead of expected values.

**Location to Check:**
- Device creation in `discover_devices_from_dhcp()` (line 878)
- Enrollment logic in API handlers

### Static IP Device Removal Issue
**Problem:** Static IP cameras disappear from dashboard after some time.

**Root Cause:** Devices with static IPs don't appear in DHCP leases, get marked as inactive, and are removed after 5 minutes by `cleanup_stale_devices()`.

**Solutions:**
1. **Enable Passive Discovery:** Already configured in `config/config.yaml`:
   - SSDP (UDP 1900): UPnP announcements
   - ONVIF (UDP 3702): IP camera discovery
   - RTSP (TCP 554): Video stream detection
   - ARP listener: Passive ARP monitoring

2. **Increase Cleanup Threshold:** In `main.py` line 531, change:
   ```python
   # From:
   self.network_scanner.cleanup_stale_devices(inactive_threshold_seconds=300)  # 5 min

   # To:
   self.network_scanner.cleanup_stale_devices(inactive_threshold_seconds=1800)  # 30 min
   ```

3. **Configure Static Leases:** Add cameras to `config/config.yaml`:
   ```yaml
   dhcp:
     static_leases:
       - mac: "c4:d8:d5:03:8e:7f"
         ip: "10.42.0.134"
         hostname: "esp32-cam-01"
       - mac: "5c:a6:e6:6a:59:18"
         ip: "10.42.0.27"
         hostname: "tapo-c100"
   ```

## Testing

1. Restart application
2. Wait 1-2 minutes for device discovery
3. Check API response shows correct manufacturer/device_type
4. Verify ESP32 camera (c4:d8:d5:03:8e:7f) identified as "Espressif / esp32_cam"
5. Confirm cameras don't disappear after 5+ minutes

## Rollback

If issues occur, restore from backup:
```bash
cp data/rakshak.db.backup.20260118_031700 data/rakshak.db
git checkout core/network_scanner.py
./start_monitoring.sh
```
