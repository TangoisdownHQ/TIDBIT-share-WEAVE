let wasmReady = null;
let wasm = null;

async function initWasm() {
  if (wasmReady) return wasmReady;
  wasmReady = (async () => {
    const response = await fetch("/vendor/tidbit_pq_wasm.wasm");
    if (!response.ok) {
      throw new Error(`Failed to load PQ wasm: ${response.status}`);
    }

    let instance;
    if ("instantiateStreaming" in WebAssembly) {
      try {
        instance = await WebAssembly.instantiateStreaming(response, {});
      } catch (_) {
        const fallbackResponse = await fetch("/vendor/tidbit_pq_wasm.wasm");
        const bytes = await fallbackResponse.arrayBuffer();
        instance = await WebAssembly.instantiate(bytes, {});
      }
    } else {
      const bytes = await response.arrayBuffer();
      instance = await WebAssembly.instantiate(bytes, {});
    }

    wasm = instance.instance.exports;
    return wasm;
  })();
  return wasmReady;
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function writeInput(bytes) {
  const ptr = wasm.wasm_alloc(bytes.length);
  new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

function readOutput(ptr, len) {
  return new Uint8Array(wasm.memory.buffer.slice(ptr, ptr + len));
}

function freeBuffer(ptr, len) {
  wasm.wasm_free(ptr, len);
}

function mldsaLengths() {
  return {
    publicKeyLen: Number(wasm.mldsa65_public_key_len()),
    secretKeyLen: Number(wasm.mldsa65_secret_key_len()),
    signatureLen: Number(wasm.mldsa65_signature_len()),
  };
}

function generateKeypair(seedB64) {
  const seed = base64ToBytes(seedB64);
  const lengths = mldsaLengths();
  const seedPtr = writeInput(seed);
  const publicKeyPtr = wasm.wasm_alloc(lengths.publicKeyLen);
  const secretKeyPtr = wasm.wasm_alloc(lengths.secretKeyLen);

  try {
    const result = wasm.mldsa65_keygen_from_seed(
      seedPtr,
      seed.length,
      publicKeyPtr,
      lengths.publicKeyLen,
      secretKeyPtr,
      lengths.secretKeyLen
    );
    if (result !== 0) {
      throw new Error(`ML-DSA key generation failed (${result})`);
    }
    return {
      public_key_b64: bytesToBase64(readOutput(publicKeyPtr, lengths.publicKeyLen)),
      secret_key_b64: bytesToBase64(readOutput(secretKeyPtr, lengths.secretKeyLen)),
    };
  } finally {
    freeBuffer(seedPtr, seed.length);
    freeBuffer(publicKeyPtr, lengths.publicKeyLen);
    freeBuffer(secretKeyPtr, lengths.secretKeyLen);
  }
}

function signMessage(secretKeyB64, messageB64, signingSeedB64) {
  const secretKey = base64ToBytes(secretKeyB64);
  const message = base64ToBytes(messageB64);
  const signingSeed = base64ToBytes(signingSeedB64);
  const lengths = mldsaLengths();
  const secretKeyPtr = writeInput(secretKey);
  const messagePtr = writeInput(message);
  const signingSeedPtr = writeInput(signingSeed);
  const signaturePtr = wasm.wasm_alloc(lengths.signatureLen);

  try {
    const result = wasm.mldsa65_sign_with_seed(
      secretKeyPtr,
      secretKey.length,
      messagePtr,
      message.length,
      signingSeedPtr,
      signingSeed.length,
      signaturePtr,
      lengths.signatureLen
    );
    if (result !== 0) {
      throw new Error(`ML-DSA signing failed (${result})`);
    }
    return {
      signature_b64: bytesToBase64(readOutput(signaturePtr, lengths.signatureLen)),
    };
  } finally {
    freeBuffer(secretKeyPtr, secretKey.length);
    freeBuffer(messagePtr, message.length);
    freeBuffer(signingSeedPtr, signingSeed.length);
    freeBuffer(signaturePtr, lengths.signatureLen);
  }
}

function verifySignature(publicKeyB64, messageB64, signatureB64) {
  const publicKey = base64ToBytes(publicKeyB64);
  const message = base64ToBytes(messageB64);
  const signature = base64ToBytes(signatureB64);
  const publicKeyPtr = writeInput(publicKey);
  const messagePtr = writeInput(message);
  const signaturePtr = writeInput(signature);

  try {
    const result = wasm.mldsa65_verify(
      publicKeyPtr,
      publicKey.length,
      messagePtr,
      message.length,
      signaturePtr,
      signature.length
    );
    if (result < 0) {
      throw new Error(`ML-DSA verification failed (${result})`);
    }
    return { verified: result === 1 };
  } finally {
    freeBuffer(publicKeyPtr, publicKey.length);
    freeBuffer(messagePtr, message.length);
    freeBuffer(signaturePtr, signature.length);
  }
}

self.onmessage = async (event) => {
  const { id, action, payload } = event.data || {};
  try {
    await initWasm();

    let result;
    switch (action) {
      case "init":
        result = { ready: true };
        break;
      case "generateKeypair":
        result = generateKeypair(payload.seed_b64);
        break;
      case "signMessage":
        result = signMessage(payload.secret_key_b64, payload.message_b64, payload.signing_seed_b64);
        break;
      case "verifySignature":
        result = verifySignature(payload.public_key_b64, payload.message_b64, payload.signature_b64);
        break;
      default:
        throw new Error(`Unsupported worker action: ${action}`);
    }

    self.postMessage({ id, ok: true, result });
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
};
