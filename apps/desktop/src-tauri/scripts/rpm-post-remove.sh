#!/bin/sh

# Tauri's RPM resource list records files while leaving nested resource
# directories implicit. Remove those directories from leaf to root when empty.
rmdir /usr/lib/FlagDeck/workers/mitmproxy/src/flagdeck_mitm 2>/dev/null || :
rmdir /usr/lib/FlagDeck/workers/mitmproxy/src 2>/dev/null || :
rmdir /usr/lib/FlagDeck/workers/mitmproxy 2>/dev/null || :
rmdir /usr/lib/FlagDeck/workers 2>/dev/null || :
rmdir /usr/lib/FlagDeck/adapters/metasploit/schemas 2>/dev/null || :
rmdir /usr/lib/FlagDeck/adapters/metasploit 2>/dev/null || :
rmdir /usr/lib/FlagDeck/adapters 2>/dev/null || :
rmdir /usr/lib/FlagDeck/config 2>/dev/null || :
rmdir /usr/lib/FlagDeck 2>/dev/null || :
exit 0
