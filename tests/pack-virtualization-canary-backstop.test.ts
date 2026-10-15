/** The check on the way out alone, in the chain and inventory tools (see tests/pack-virtualization-canary-lib.ts). */
import { registerBackstopAlone } from "./pack-virtualization-canary-lib.ts";

registerBackstopAlone(["snapshot_chain_check", "virtualization_inventory"]);
