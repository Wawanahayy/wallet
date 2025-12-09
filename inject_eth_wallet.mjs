import { keccak256 } from "@ethersproject/keccak256";
import { arrayify } from "@ethersproject/bytes";
import { SigningKey } from "@ethersproject/signing-key";
import { computeAddress } from "@ethersproject/transactions";

export async function injectEthereumWallet(page, privateKey) {
  const pk = privateKey.startsWith("0x")
    ? privateKey
    : "0x" + privateKey;

  const signer = new SigningKey(pk);
  const address = computeAddress(pk);

  await page.exposeFunction("wallet_signMessage", async (msgHex) => {
    const msg = arrayify(msgHex);
    const digest = keccak256(msg);
    return signer.signDigest(digest).serialized;
  });

  await page.exposeFunction("wallet_getAddress", async () => address);

  await page.evaluateOnNewDocument(() => {
    window.ethereum = {
      isMetaMask: true,
      selectedAddress: null,
      chainId: "0x1",

      async request({ method, params }) {
        if (method === "eth_requestAccounts" || method === "eth_accounts") {
          const addr = await window.wallet_getAddress();
          window.ethereum.selectedAddress = addr;
          return [addr];
        }

        if (method === "personal_sign") {
          const msg = params[0];
          const hex =
            msg.startsWith("0x")
              ? msg
              : "0x" + Array.from(new TextEncoder().encode(msg))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join("");

          return await window.wallet_signMessage(hex);
        }

        if (method === "eth_chainId") {
          return "0x1";
        }

        throw new Error("Unknown RPC: " + method);
      },
    };

    console.log("Injected Fake Ethereum Wallet ✔");
  });

  console.log("🔥 Fake EVM Wallet Injected, Address:", address);
}
