(function() {
    // ---------- DOM Elements ----------
    const inputField = document.getElementById('inputText');
    const passField = document.getElementById('passphrase');
    const outputField = document.getElementById('outputText');
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const copyBtn = document.getElementById('copyBtn');
    const clearBtn = document.getElementById('clearBtn');
  
    // Helper: show standard output (removes any red/bold styling)
    function setOutput(text, isError = false) {
      outputField.value = text;
      if (isError) {
        // apply red bold style via inline style
        outputField.style.color = '#b91c1c';
        outputField.style.fontWeight = 'bold';
        outputField.style.background = '#fff6f5';
      } else {
        outputField.style.color = '#0f172a';
        outputField.style.fontWeight = 'normal';
        outputField.style.background = '#fefcf5';
      }
    }
  
    // reset output style to neutral when clearing
    function resetOutputStyle() {
      outputField.style.color = '#0f172a';
      outputField.style.fontWeight = 'normal';
      outputField.style.background = '#fefcf5';
    }
  
    // ------------------------------------------------------------------
    // AES-256-GCM with Web Crypto API
    // Format: base64( salt (16B) + iv (12B) + ciphertext + authTag(16B) )
    // ------------------------------------------------------------------
  
    // convert ArrayBuffer <-> Base64
    function bufToBase64(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }
  
    function base64ToBuf(base64) {
      const binary = atob(base64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    }
  
    // Derive AES-256 key from passphrase using PBKDF2
    async function deriveKey(passphrase, salt) {
      const encoder = new TextEncoder();
      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
      );
      return window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 210000,   // OWASP recommended
          hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    }
  
    // Encrypt plaintext using passphrase
    async function aes256GcmEncrypt(plaintext, passphrase) {
      if (!plaintext || plaintext.trim() === "") {
        throw new Error("Nothing to encrypt. Please enter text.");
      }
      if (!passphrase) {
        throw new Error("Passphrase is required for encryption.");
      }
  
      const encoder = new TextEncoder();
      const data = encoder.encode(plaintext);
      
      // Generate random salt (16 bytes) and iv (12 bytes for GCM)
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      const key = await deriveKey(passphrase, salt);
      
      // Encrypt
      const encrypted = await window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128,
        },
        key,
        data
      );
      
      // Extract ciphertext and authTag
      const encryptedArray = new Uint8Array(encrypted);
      const tagLength = 16;
      const ciphertext = encryptedArray.slice(0, encryptedArray.length - tagLength);
      const authTag = encryptedArray.slice(encryptedArray.length - tagLength);
      
      // Concatenate: salt + iv + ciphertext + authTag
      const saltBuf = salt.buffer;
      const ivBuf = iv.buffer;
      const ciphertextBuf = ciphertext.buffer;
      const tagBuf = authTag.buffer;
      
      const totalLength = saltBuf.byteLength + ivBuf.byteLength + ciphertextBuf.byteLength + tagBuf.byteLength;
      const resultBuffer = new Uint8Array(totalLength);
      let offset = 0;
      resultBuffer.set(new Uint8Array(saltBuf), offset);
    offset += saltBuf.byteLength;
    resultBuffer.set(new Uint8Array(ivBuf), offset);
    offset += ivBuf.byteLength;
    resultBuffer.set(new Uint8Array(ciphertextBuf), offset);
    offset += ciphertextBuf.byteLength;
    resultBuffer.set(new Uint8Array(tagBuf), offset);
    
    return bufToBase64(resultBuffer.buffer);
  }

  // Decrypt from base64 structured blob using passphrase
  async function aes256GcmDecrypt(encryptedBase64, passphrase) {
    if (!encryptedBase64 || encryptedBase64.trim() === "") {
      throw new Error("No encrypted data provided.");
    }
    if (!passphrase) {
      throw new Error("Passphrase is required for decryption.");
    }
    
    let fullBuffer;
    try {
      fullBuffer = base64ToBuf(encryptedBase64);
    } catch (e) {
      throw new Error("Invalid encrypted format: corrupted base64.");
    }
    
    const dataArray = new Uint8Array(fullBuffer);
    const SALT_LEN = 16;
    const IV_LEN = 12;
    const TAG_LEN = 16;
    
    if (dataArray.length < SALT_LEN + IV_LEN + TAG_LEN + 1) {
      throw new Error("Malformed ciphertext: data too short.");
    }
    
    const salt = dataArray.slice(0, SALT_LEN);
    const iv = dataArray.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const encryptedPortion = dataArray.slice(SALT_LEN + IV_LEN);
    if (encryptedPortion.length < TAG_LEN) {
      throw new Error("Invalid encrypted payload: missing authentication tag.");
    }
    const ciphertext = encryptedPortion.slice(0, encryptedPortion.length - TAG_LEN);
    const authTag = encryptedPortion.slice(encryptedPortion.length - TAG_LEN);
    
    // Rebuild the exact encrypted buffer that WebCrypto expects
    const combinedForDecrypt = new Uint8Array(ciphertext.length + authTag.length);
    combinedForDecrypt.set(ciphertext, 0);
    combinedForDecrypt.set(authTag, ciphertext.length);
    
    // Derive key from passphrase + extracted salt
    const key = await deriveKey(passphrase, salt);
    
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128,
        },
        key,
        combinedForDecrypt.buffer
      );
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (err) {
      throw new Error("Decryption failed: wrong passphrase or corrupted data.");
    }
  }

  // ---------- UI handlers ----------
  async function handleEncrypt() {
    const plaintext = inputField.value;
    const pass = passField.value;
    if (!plaintext) {
      setOutput("⚠️ Nothing to encrypt. Please enter text in the input field.", true);
      return;
    }
    if (!pass) {
      setOutput("🔐 Passphrase is empty. Please enter a secret passphrase.", true);
      return;
    }
    
    try {
      const encryptedResult = await aes256GcmEncrypt(plaintext, pass);
      setOutput(encryptedResult, false);
    } catch (err) {
      setOutput(`❌ Encryption error: ${err.message}`, true);
    }
  }
  
  async function handleDecrypt() {
    const cipherInput = inputField.value;
    const pass = passField.value;
    if (!cipherInput) {
      setOutput("⚠️ No ciphertext to decrypt. Please paste encrypted string in the input field.", true);
      return;
    }
    if (!pass) {
      setOutput("🔐 Passphrase required to decrypt.", true);
      return;
    }
    
    try {
      const decryptedText = await aes256GcmDecrypt(cipherInput, pass);
      setOutput(decryptedText, false);
    } catch (err) {
      let userMessage = "❌ Decryption failed: invalid passphrase or corrupted/malformed ciphertext.";
      setOutput(userMessage, true);
    }
  }
  
  function handleCopy() {
    const outputContent = outputField.value;
    if (!outputContent) {
      const originalOutput = outputField.value;
      setOutput("📭 Nothing to copy. Output is empty.", true);
      setTimeout(() => {
        if (outputField.value === "📭 Nothing to copy. Output is empty.") {
          setOutput(originalOutput === "" ? "" : originalOutput, false);
          if (originalOutput === "") resetOutputStyle();
} else if (originalOutput !== "") {
    setOutput(originalOutput, false);
  } else {
    setOutput("", false);
  }
}, 1500);
return;
}

navigator.clipboard.writeText(outputContent).then(() => {
const previous = outputField.value;
const wasErrorStyle = outputField.style.color === 'rgb(185, 28, 28)';
setOutput("✓ Copied to clipboard!", false);
setTimeout(() => {
  setOutput(previous, wasErrorStyle);
}, 1200);
}).catch(() => {
setOutput("❌ Failed to copy. Manual copy required.", true);
});
}

function handleClear() {
inputField.value = "";
passField.value = "";
setOutput("", false);
resetOutputStyle();
inputField.focus();
}

// attach event listeners
encryptBtn.addEventListener('click', handleEncrypt);
decryptBtn.addEventListener('click', handleDecrypt);
copyBtn.addEventListener('click', handleCopy);
clearBtn.addEventListener('click', handleClear);
})();
