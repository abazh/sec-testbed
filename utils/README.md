# Utilities Directory

Simple utility scripts for managing the security testbed.

## Scripts

### `cleanup.sh` - Clean old files
```bash
./utils/cleanup.sh [days]
```
- Default: keeps files from last 7 days
- Examples:
  - `./utils/cleanup.sh` - Clean files older than 7 days
  - `./utils/cleanup.sh 3` - Clean files older than 3 days
  - `./utils/cleanup.sh 0` - Clean all files

### `status.sh` - Show testbed status
```bash
./utils/status.sh
```
Shows:
- Container status
- Data directory usage
- Recent files
- Network information

### `reset.sh` - Reset everything
```bash
./utils/reset.sh
```
- Stops all containers
- Cleans all data
- Removes Docker volumes and networks

### `archive.sh` - Archive data for research
```bash
./utils/archive.sh
```
- Creates timestamped archive of all data
- Excludes temporary files
- Shows archive contents and size

## Quick Commands

```bash
# Check status
./utils/status.sh

# Clean old data (keep last 3 days)
./utils/cleanup.sh 3

# Start fresh
./utils/reset.sh

# Archive current data
./utils/archive.sh
```
