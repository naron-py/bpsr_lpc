"""
Frida script to capture RPC method IDs from a running game client.

Run this while logging into the game to capture the exact method_id
values for LoadMapSuccess and TransferLoadingEnd.

Usage:
  python tools/frida_method_ids.py

Requires: pip install frida
The game (StarSEA.exe) must already be running.
"""

import frida
import sys
import time

HOOK_SCRIPT = r"""
try {
    var module = Process.getModuleByName("GameAssembly.dll");
    console.log("[+] GameAssembly.dll base: " + module.base);

    // ====================================================================
    // Hook ProxyCallSync to dump ALL method IDs
    // RVA: 0x6BC2830 (ProxyCallSync extension method)
    // Signature: ProxyCallSync(IRpc rpc, IProxy pxy, uint methodId,
    //            byte[] data, uint dataSize, bool useFrame, ...)
    // ====================================================================

    // ProxyCallSync is a static extension method:
    //   arg0 = rpc, arg1 = pxy, arg2 = methodId, arg3 = data,
    //   arg4 = dataSize, arg5 = useFrame
    Interceptor.attach(module.base.add(0x6BC2830), {
        onEnter: function(args) {
            var methodId = args[2].toUInt32();
            var dataSize = args[4].toUInt32();
            var useFrame = args[5].toUInt32();

            var hex = "0x" + methodId.toString(16).padStart(8, '0');
            console.log("[ProxyCallSync] methodId=" + hex + " (" + methodId + ")" +
                        " dataSize=" + dataSize + " useFrame=" + useFrame);

            send({
                type: "proxy_call",
                methodId: methodId,
                methodIdHex: hex,
                dataSize: dataSize,
                useFrame: useFrame
            });
        }
    });

    // ====================================================================
    // Also hook ProxyNotify for Notify-type calls
    // RVA: varies — hook the IBufferMessage overload
    // ProxyNotify(IProxy pxy, uint methodId, byte[] data, uint dataSize, bool addToFrame)
    // ====================================================================

    // Hook ProxyCall (IBufferMessage overload) at RVA 0x6BC8570
    Interceptor.attach(module.base.add(0x6BC8570), {
        onEnter: function(args) {
            var methodId = args[1].toUInt32();
            var addToFrame = args[3].toUInt32();

            var hex = "0x" + methodId.toString(16).padStart(8, '0');
            console.log("[ProxyCall-Msg] methodId=" + hex + " (" + methodId + ")" +
                        " addToFrame=" + addToFrame);

            send({
                type: "proxy_call_msg",
                methodId: methodId,
                methodIdHex: hex,
                addToFrame: addToFrame
            });
        }
    });

    // ====================================================================
    // Hook specific RPC methods for labeling
    // ====================================================================

    // LoadMapSuccess RVA: 0x518D9C0
    Interceptor.attach(module.base.add(0x518D9C0), {
        onEnter: function(args) {
            console.log("\n*** LoadMapSuccess CALLED ***");
            send({ type: "label", method: "LoadMapSuccess" });
        }
    });

    // TransferLoadingEnd RVA: 0x518E560
    Interceptor.attach(module.base.add(0x518E560), {
        onEnter: function(args) {
            console.log("\n*** TransferLoadingEnd CALLED ***");
            send({ type: "label", method: "TransferLoadingEnd" });
        }
    });

    // ReqSwitchScene RVA: 0x518D7C0 (known: 0x50002)
    Interceptor.attach(module.base.add(0x518D7C0), {
        onEnter: function(args) {
            console.log("\n*** ReqSwitchScene CALLED ***");
            send({ type: "label", method: "ReqSwitchScene" });
        }
    });

    console.log("[*] All hooks applied. Log in to the game now.");
    console.log("[*] The next ProxyCall after 'LoadMapSuccess CALLED' shows the method ID.");

} catch (e) {
    console.log("[-] Error: " + e.stack);
}
"""

last_label = None
method_map = {}

def on_message(message, data):
    global last_label
    if message['type'] == 'send':
        payload = message['payload']
        if isinstance(payload, dict):
            msg_type = payload.get('type', '')

            if msg_type == 'label':
                last_label = payload['method']

            elif msg_type in ('proxy_call', 'proxy_call_msg'):
                method_id = payload['methodId']
                hex_id = payload['methodIdHex']

                if last_label:
                    method_map[last_label] = hex_id
                    print(f"\n{'='*50}")
                    print(f"  {last_label} → methodId = {hex_id} ({method_id})")
                    print(f"{'='*50}")
                    last_label = None

                    # Print summary after each discovery
                    if method_map:
                        print("\n--- Method ID Map ---")
                        for name, mid in sorted(method_map.items()):
                            print(f"  {name}: {mid}")
                        print("---")
    elif message['type'] == 'error':
        print(f"[ERROR] {message['description']}")


def main():
    target = "StarSEA.exe"
    print(f"[*] Frida Method ID Capture Tool")
    print(f"[*] Attaching to {target}...")

    try:
        session = frida.attach(target)
        print("[+] Attached!")

        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()

        print("[!] Hooks active. Log in to the game now.")
        print("[!] Press Ctrl+C to stop.\n")

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n--- Final Method ID Map ---")
        for name, mid in sorted(method_map.items()):
            print(f"  {name}: {mid}")
        print("---")
        session.detach()
    except frida.ProcessNotFoundError:
        print(f"[-] {target} not found. Start the game first.")
    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    main()
