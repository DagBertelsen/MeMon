# Implementation Plan: Auto Responder and Timer Trigger Mode Support

## Overview

Add support for both Auto Responder (immediate status response) and Timer Trigger (existing scheduled monitoring) modes to MeMon.

**Detection**: Auto Responder mode detected via `MESSAGE` or `TRIGGER` environment variables (per MeshMonitor documentation)

## Key Changes

### 1. New Functions (memon.py)

#### `detect_execution_mode() -> str`
- **Location**: After utility functions (~line 129)
- **Logic**: Check for `MESSAGE` or `TRIGGER` env vars
- **Return**: `"auto_responder"` or `"timer_trigger"`

```python
def detect_execution_mode() -> str:
    if os.environ.get("MESSAGE") or os.environ.get("TRIGGER"):
        return "auto_responder"
    return "timer_trigger"
```

#### `format_status_report(router_ok, failed_dns, all_dns, dns_checks) -> str`
- **Location**: After `_format_alert_message()` (~line 825)
- **Logic**: Format status message based on check results
- **Output formats**:
  - Router DOWN: `"Router DOWN"`
  - Router OK, no DNS: `"Router OK"`
  - All DNS fail: `"Router OK, All DNS FAIL"`
  - Mixed: `"Router OK, DNS: Google OK, Cloudflare FAIL, Altibox OK"`

#### `_get_dns_display_name(check, index) -> str`
- **Location**: Helper function near `format_status_report()`
- **Logic**: Extract display name from DNS check config or generate fallback

### 2. Modified Functions

#### `main()` (lines 847-931)
**Add mode detection** (after config loading):
```python
mode = detect_execution_mode()
```

**Branch execution paths**:
```python
# Common: Load config, perform checks, classify status

if mode == "auto_responder":
    # Always emit status report immediately
    message = format_status_report(router_ok, failed_dns, all_dns, dns_checks)
    emit_alert(message)
    return  # Skip state operations
else:
    # Existing Timer Trigger logic (unchanged)
    # - Load state
    # - Check mustFailCount, backoff
    # - Fire alerts conditionally
    # - Save state
```

### 3. Files to Modify

#### Primary Implementation
- **[memon.py](../../memon.py)**
  - Add 3 new functions (~100 lines)
  - Modify `main()` to branch on mode (~50 line change)
  - Reuse existing functions: `check_router()`, `check_all_dns()`, `classify_status()`, `emit_alert()`

#### Testing
- **[memon.test.py](../../memon.test.py)**
  - Add `TestModeDetection` class (4 tests)
  - Add `TestStatusReportFormatting` class (6 tests)
  - Add `TestAutoResponderMode` class (8 integration tests)
  - Add `TestTimerTriggerModeUnchanged` class (5 regression tests)

#### Documentation
- **[README.md](../../README.md)**
  - Add Auto Responder mode section
  - Document environment variable detection
  - Add example output formats

- **[AGENTS.md](../../AGENTS.md)**
  - Update core requirements with both modes
  - Distinguish alert logic between modes

## Behavior Specification

### Auto Responder Mode
- **Trigger**: User sends message matching pattern
- **Detection**: `MESSAGE` or `TRIGGER` env var present
- **Behavior**:
  - Bypass `mustFailCount` (no failure streak checking)
  - Bypass `alertBackoffSeconds` (no backoff)
  - Skip state file operations (stateless)
  - Always emit status report response
- **Output**: Current status of router and all DNS checks

### Timer Trigger Mode (Existing)
- **Trigger**: Scheduled via cron
- **Detection**: No special env vars
- **Behavior**: Unchanged from current implementation
  - Load/save state file
  - Respect `mustFailCount` threshold
  - Respect `alertBackoffSeconds` backoff
  - Emit alerts only when conditions met
- **Output**: Alert messages when failures/recovery detected

## Implementation Steps

1. **Add mode detection function**
   - Simple env var check
   - Add tests with mocked environment

2. **Add status report formatter**
   - Handle 4 message formats (router down, router ok, all dns fail, mixed)
   - Add unit tests for each format
   - Handle edge cases (no DNS checks, long names)

3. **Modify main() function**
   - Add mode detection at start
   - Branch Auto Responder path (skip state operations)
   - Keep Timer Trigger path unchanged

4. **Add integration tests**
   - Auto Responder: always emits, no state I/O
   - Timer Trigger: verify existing behavior unchanged

5. **Update documentation**
   - README examples
   - AGENTS.md requirements

## Critical Code Locations

**State management** (must skip in Auto Responder):
- `load_state()` - line 186
- `save_state()` - line 219
- `_update_state()` - line 827

**Alert decisions** (bypass in Auto Responder):
- `should_fire_down_alert()` - line 678 (uses mustFailCount, backoff)
- `should_fire_up_alert()` - line 708
- `should_fire_partial_recovery_alert()` - line 722

**Reusable functions** (used by both modes):
- `check_router()` - line 330
- `check_all_dns()` - line 585
- `classify_status()` - line 649
- `emit_alert()` - line 770

## Edge Cases

1. **No DNS checks configured**: Return "Router OK"
2. **Empty DNS names**: Use fallback "DNS-0", "DNS-1", etc.
3. **Long DNS list**: Truncate to MAX_MESSAGE_LENGTH (200 chars)
4. **Both env vars present**: Detect as Auto Responder
5. **Timeout during checks**: Emit best-effort status
6. **Config file missing**: Error in both modes (unchanged)

## Backward Compatibility

**Guaranteed**:
- Timer Trigger mode behavior unchanged
- State file format unchanged
- Configuration schema unchanged
- Message templates unchanged
- All existing tests pass

**New**:
- Auto Responder mode (new functionality)
- No breaking changes

## Verification Plan

### Unit Tests
```bash
python memon.test.py TestModeDetection -v
python memon.test.py TestStatusReportFormatting -v
```

### Integration Tests
```bash
# Auto Responder mode
MESSAGE="status" python memon.py

# Timer Trigger mode (existing)
python memon.py
```

### Full Test Suite
```bash
python memon.test.py -v 2>&1
```

### Manual Testing
```bash
# Simulate Auto Responder
export MESSAGE="check network"
export TRIGGER="check network"
python memon.py
# Expected: Status report output

# Simulate Timer Trigger
unset MESSAGE
unset TRIGGER
python memon.py
# Expected: Conditional alert output (existing behavior)
```

## Success Criteria

- ✅ Mode detection works via environment variables
- ✅ Auto Responder always emits status report
- ✅ Auto Responder skips state file operations
- ✅ Auto Responder bypasses mustFailCount and backoff
- ✅ Timer Trigger behavior unchanged
- ✅ All tests pass (existing + new)
- ✅ Documentation updated
- ✅ No breaking changes
