"use strict";

const E2EE_ITERATIONS = 310000;

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlToBytes(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  return base64ToBytes(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function deriveBundleKey(passphrase, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: E2EE_ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptKeyBundle(bundle, passphrase) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveBundleKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify(bundle)),
  );
  return {
    version: 1,
    kdf: "PBKDF2-SHA256",
    iterations: E2EE_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptKeyBundle(encrypted, passphrase) {
  if (
    encrypted.version !== 1 ||
    encrypted.kdf !== "PBKDF2-SHA256" ||
    encrypted.iterations !== E2EE_ITERATIONS
  ) {
    throw new Error("Unsupported encrypted recovery bundle format.");
  }
  const key = await deriveBundleKey(passphrase, base64ToBytes(encrypted.salt));
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(encrypted.iv) },
    key,
    base64ToBytes(encrypted.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function csrfToken(form) {
  return form.querySelector('input[name="csrf_token"]')?.value || "";
}

async function submitJson(url, token, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": token,
    },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

const enrollmentForm = document.getElementById("e2ee-enrollment-form");
if (enrollmentForm) {
  enrollmentForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = document.getElementById("e2ee-status");
    const passphrase = enrollmentForm.elements.passphrase.value;
    if (passphrase !== enrollmentForm.elements.confirm_passphrase.value) {
      status.textContent = "The passphrases do not match.";
      return;
    }

    const button = enrollmentForm.querySelector('button[type="submit"]');
    button.disabled = true;
    status.textContent = "Generating browser-held keys and certificate…";
    try {
      const signingKeys = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      const encryptionKeys = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
      );
      const signingPrivate = new Uint8Array(
        await crypto.subtle.exportKey("pkcs8", signingKeys.privateKey),
      );
      const encryptionPrivate = new Uint8Array(
        await crypto.subtle.exportKey("pkcs8", encryptionKeys.privateKey),
      );
      const signingPublic = new Uint8Array(
        await crypto.subtle.exportKey("spki", signingKeys.publicKey),
      );
      const encryptionPublic = new Uint8Array(
        await crypto.subtle.exportKey("spki", encryptionKeys.publicKey),
      );
      const keyBundle = {
        signing_private_key: bytesToBase64(signingPrivate),
        encryption_private_key: bytesToBase64(encryptionPrivate),
        signing_public_key: bytesToBase64(signingPublic),
        encryption_public_key: bytesToBase64(encryptionPublic),
      };
      const encryptedKeyBundle = await encryptKeyBundle(keyBundle, passphrase);
      const recoveryCode = bytesToBase64Url(randomBytes(32));
      const recoveryBundle = await encryptKeyBundle(keyBundle, recoveryCode);
      const enrollment = await submitJson(
        window.location.pathname,
        csrfToken(enrollmentForm),
        {
          signing_public_key: bytesToBase64(signingPublic),
          encryption_public_key: bytesToBase64(encryptionPublic),
          encrypted_key_bundle: encryptedKeyBundle,
        },
      );
      const recoveryFile = {
        format: "secure-exchange-recovery-v1",
        username: document.querySelector(".sidebar-account strong")?.textContent || "",
        certificate_code: enrollment.certificate_code,
        signing_public_key: bytesToBase64(signingPublic),
        encryption_public_key: bytesToBase64(encryptionPublic),
        encrypted_key_bundle: recoveryBundle,
      };
      document.getElementById("e2ee-recovery-code").textContent = recoveryCode;
      document.getElementById("e2ee-recovery-download").href = URL.createObjectURL(
        new Blob([JSON.stringify(recoveryFile, null, 2)], { type: "application/json" }),
      );
      document.getElementById("e2ee-certificate-code").textContent = enrollment.certificate_code;
      document.getElementById("e2ee-recovery").hidden = false;
      enrollmentForm.hidden = true;
      status.textContent = "Keys enrolled. Save the recovery file and recovery code before leaving this page.";
    } catch (error) {
      status.textContent = error.message;
      button.disabled = false;
    }
  });
}

const restoreForm = document.getElementById("e2ee-restore-form");
if (restoreForm) {
  restoreForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = document.getElementById("e2ee-status");
    const button = restoreForm.querySelector('button[type="submit"]');
    button.disabled = true;
    status.textContent = "Restoring browser-held keys…";
    try {
      const file = restoreForm.elements.recovery_file.files[0];
      const recoveryCode = restoreForm.elements.recovery_code.value;
      const newPassphrase = restoreForm.elements.new_passphrase.value;
      const recovery = JSON.parse(await file.text());
      if (recovery.format !== "secure-exchange-recovery-v1") {
        throw new Error("This is not a supported recovery file.");
      }
      const keyBundle = await decryptKeyBundle(recovery.encrypted_key_bundle, recoveryCode);
      const newEncryptedKeyBundle = await encryptKeyBundle(
        keyBundle,
        newPassphrase,
      );
      await submitJson(
        "/account/keys/restore",
        csrfToken(restoreForm),
        {
          signing_public_key: recovery.signing_public_key,
          encryption_public_key: recovery.encryption_public_key,
          encrypted_key_bundle: newEncryptedKeyBundle,
        },
      );
      status.textContent = "Keys restored. You can now send and decrypt messages from this browser.";
      restoreForm.hidden = true;
    } catch (error) {
      status.textContent = error.message;
      button.disabled = false;
    }
  });
}

async function fetchKeyBundle(passphrase) {
  let response;
  try {
    response = await fetch("/api/client-key-bundle", {
      signal: AbortSignal.timeout(15000),
    });
  } catch (error) {
    if (error.name === "TimeoutError") {
      throw new Error("Loading your encrypted signing key timed out. Please try again.");
    }
    throw error;
  }
  if (response.redirected) {
    throw new Error("Your session has expired. Sign in again before signing.");
  }
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("The signing-key service returned an invalid response.");
  }
  if (!response.ok) throw new Error(data.error || "Could not load your encrypted key bundle.");
  return decryptKeyBundle(data.bundle, passphrase);
}

function fromBase64(value) {
  return base64ToBytes(value).buffer;
}

function safeDownloadName(value, fallback) {
  return value.split(/[\\/]/).pop().replace(/[^a-z0-9._-]+/gi, "_").slice(0, 160) || fallback;
}

const sendForm = document.getElementById("e2ee-send-form");
if (sendForm) {
  document.getElementById("e2ee-copy-key").addEventListener("click", async () => {
    const key = document.getElementById("e2ee-one-time-key").textContent;
    const copyStatus = document.getElementById("e2ee-copy-status");
    try {
      await navigator.clipboard.writeText(key);
      copyStatus.textContent = "Key copied. Share it with the recipient separately.";
    } catch (error) {
      copyStatus.textContent = `Copy failed. Select and copy the key manually. (${error.message})`;
    }
  });

  sendForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = document.getElementById("e2ee-status");
    const button = sendForm.querySelector('button[type="submit"]');
    button.disabled = true;
    status.textContent = "Signing and encrypting in your browser…";
    try {
      const passphrase = sendForm.elements.passphrase.value;
      const keyBundle = await fetchKeyBundle(passphrase);
      const signingKey = await crypto.subtle.importKey(
        "pkcs8",
        fromBase64(keyBundle.signing_private_key),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      );
      const recipientId = sendForm.elements.recipient_id.value;
      const certificateSelect = sendForm.elements.certificate_id;
      const certificateOption = certificateSelect.selectedOptions[0];
      const certificateResponse = await fetch(
        `/api/certificates/${encodeURIComponent(certificateOption.dataset.serial)}/trust`,
      );
      const certificateTrust = await certificateResponse.json();
      if (!certificateResponse.ok || !certificateTrust.trusted) {
        throw new Error("Your signing certificate is not active and trusted.");
      }
      const message = sendForm.elements.document_text.value;
      const uploadedFile = sendForm.elements.document_file.files[0];
      if (uploadedFile && message.trim()) {
        throw new Error("Paste a message or attach a PDF, not both.");
      }
      if (!uploadedFile && !message.trim()) {
        throw new Error("Enter message content or attach a PDF.");
      }
      if (
        uploadedFile &&
        uploadedFile.type !== "application/pdf" &&
        !uploadedFile.name.toLowerCase().endsWith(".pdf")
      ) {
        throw new Error("Only PDF documents can be attached.");
      }
      const title = sendForm.elements.title.value;
      const senderId = Number(sendForm.dataset.senderId);
      const recipientIdNumber = Number(recipientId);
      if (uploadedFile && uploadedFile.size > 4 * 1024 * 1024) {
        throw new Error("PDF documents must be no larger than 4 MB.");
      }
      const messageBytes = uploadedFile
        ? new Uint8Array(await uploadedFile.arrayBuffer())
        : new TextEncoder().encode(message);
      if (
        uploadedFile &&
        new TextDecoder().decode(messageBytes.slice(0, 5)) !== "%PDF-"
      ) {
        throw new Error("The attached file is not a valid PDF document.");
      }
      if (messageBytes.byteLength > 6 * 1024 * 1024) {
        throw new Error("Messages must be no larger than 6 MB.");
      }
      const contentType = uploadedFile ? "application/pdf" : "text/plain";
      const filename = uploadedFile ? safeDownloadName(uploadedFile.name, "document.pdf") : "";
      const contentHash = bytesToBase64(
        new Uint8Array(await crypto.subtle.digest("SHA-256", messageBytes)),
      );
      const signaturePayload = JSON.stringify({
        version: 2,
        title,
        sender_id: senderId,
        recipient_id: recipientIdNumber,
        content_type: contentType,
        filename,
        content_hash: contentHash,
      });
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        signingKey,
        new TextEncoder().encode(signaturePayload),
      );
      const envelope = {
        version: 2,
        title,
        sender_id: senderId,
        recipient_id: recipientIdNumber,
        content_type: contentType,
        filename,
        content_hash: contentHash,
        content_base64: bytesToBase64(messageBytes),
        signature: bytesToBase64(new Uint8Array(signature)),
        signer_certificate_serial: certificateOption.dataset.serial,
        signer_certificate_pem: certificateTrust.certificate_pem,
      };
      const rawMessageKey = randomBytes(32);
      const oneTimeKey = bytesToBase64Url(rawMessageKey);
      const messageKey = await crypto.subtle.importKey(
        "raw",
        rawMessageKey,
        { name: "AES-GCM" },
        false,
        ["encrypt"],
      );
      const iv = randomBytes(12);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        messageKey,
        new TextEncoder().encode(JSON.stringify(envelope)),
      );
      const sent = await submitJson(
        window.location.pathname,
        csrfToken(sendForm),
        {
          title,
          recipient_id: recipientId,
          certificate_id: certificateSelect.value,
          payload: {
            version: 3,
            iv: bytesToBase64(iv),
            ciphertext: bytesToBase64(new Uint8Array(encrypted)),
          },
        },
      );
      document.getElementById("e2ee-one-time-key").textContent = oneTimeKey;
      document.getElementById("e2ee-sent-message-id").textContent = sent.document_id;
      document.getElementById("e2ee-sent-key").hidden = false;
      sendForm.hidden = true;
      status.textContent = "Message encrypted in your browser and sent.";
    } catch (error) {
      status.textContent = error.message;
      button.disabled = false;
    }
  });
}

const signForm = document.getElementById("sign-document-form");
if (signForm?.elements.passphrase) {
  signForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = document.getElementById("e2ee-sign-status");
    const button = signForm.querySelector('button[type="submit"]');
    const passphraseField = signForm.elements.passphrase;
    const passphrase = passphraseField.value;
    const originalButtonLabel = button.textContent;
    button.disabled = true;
    button.textContent = "Checking document…";
    status.textContent = "Checking document…";
    try {
      const uploadedFile = signForm.elements.document_file.files[0];
      const text = signForm.elements.document_text.value;
      if (Boolean(uploadedFile) === Boolean(text)) {
        throw new Error("Provide either pasted text or one file, not both.");
      }
      let content;
      if (uploadedFile) {
        if (uploadedFile.size > 10 * 1024 * 1024) {
          throw new Error("The uploaded file exceeds the 10 MB limit.");
        }
        const filename = uploadedFile.name.toLowerCase();
        if (!filename.endsWith(".txt") && !filename.endsWith(".pdf")) {
          throw new Error("Upload a .txt or .pdf file.");
        }
        content = await uploadedFile.arrayBuffer();
        if (filename.endsWith(".pdf")) {
          if (
            content.byteLength < 5 ||
            new TextDecoder().decode(new Uint8Array(content, 0, 5)) !== "%PDF-"
          ) {
            throw new Error("The uploaded file is not a valid PDF.");
          }
        } else {
          new TextDecoder("utf-8", { fatal: true }).decode(content);
        }
      } else {
        content = new TextEncoder().encode(text);
      }

      button.textContent = "Unlocking signing key…";
      status.textContent = "Unlocking your browser-held signing key…";
      const keyBundle = await fetchKeyBundle(passphrase);
      const signingKey = await crypto.subtle.importKey(
        "pkcs8",
        fromBase64(keyBundle.signing_private_key),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      );
      button.textContent = "Signing locally…";
      status.textContent = "Creating the signature locally…";
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        signingKey,
        content,
      );
      signForm.elements.signature_hex.value = Array.from(new Uint8Array(signature))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
      button.textContent = "Saving document…";
      status.textContent = "Saving the signed document…";
      passphraseField.value = "";
      passphraseField.remove();
      HTMLFormElement.prototype.submit.call(signForm);
    } catch (error) {
      status.textContent = error.message;
      button.disabled = false;
      button.textContent = originalButtonLabel;
    }
  });
}

function pdfBytes(title, content) {
  const clean = (value) => Array.from(value, (char) => {
    const code = char.codePointAt(0);
    return code <= 255 ? code : 63;
  });
  const escapePdf = (value) =>
    clean(value).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const contentLines = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = clean(rawLine);
    if (!line.length) {
      contentLines.push([]);
      continue;
    }
    for (let offset = 0; offset < line.length; offset += 88) {
      contentLines.push(line.slice(offset, offset + 88));
    }
  }
  const pageLines = [];
  for (let index = 0; index < contentLines.length; index += 48) {
    pageLines.push(contentLines.slice(index, index + 48));
  }
  if (!pageLines.length) pageLines.push([]);
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${pageLines.map((_, index) => `${4 + index * 2} 0 R`).join(" ")}] /Count ${pageLines.length} >>`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
  ];
  for (const [index, lines] of pageLines.entries()) {
    const pageId = 4 + index * 2;
    const contentId = pageId + 1;
    const commands = ["BT", "/F1 11 Tf", "50 760 Td", "14 TL"];
    if (index === 0) commands.push(`<${escapePdf(title)}> Tj`, "T*");
    for (const line of lines) {
      commands.push(`<${line.map((byte) => byte.toString(16).padStart(2, "0")).join("")}> Tj`, "T*");
    }
    commands.push("ET");
    const stream = commands.join("\n");
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`,
      `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    );
  }
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  for (const [index, object] of objects.entries()) {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  }
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return Uint8Array.from(pdf, (character) => character.charCodeAt(0));
}

const decryptForm = document.getElementById("e2ee-decrypt-form");
if (decryptForm) {
  decryptForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = document.getElementById("e2ee-status");
    const button = decryptForm.querySelector('button[type="submit"]');
    button.disabled = true;
    status.textContent = "Decrypting and verifying locally in your browser…";
    try {
      const payload = JSON.parse(document.getElementById("e2ee-payload").textContent);
      const metadata = JSON.parse(
        document.getElementById("e2ee-message-metadata").textContent,
      );
      let messageKey;
      if (payload.version === 3 && metadata.format_version === 3) {
        const rawMessageKey = base64UrlToBytes(decryptForm.elements.message_key.value.trim());
        if (rawMessageKey.byteLength !== 32) {
          throw new Error("The one-time decryption key is invalid.");
        }
        messageKey = await crypto.subtle.importKey(
          "raw",
          rawMessageKey,
          { name: "AES-GCM" },
          false,
          ["decrypt"],
        );
      } else if (payload.version === 2 && metadata.format_version === 2) {
        const keyBundle = await fetchKeyBundle(decryptForm.elements.passphrase.value);
        const privateKey = await crypto.subtle.importKey(
          "pkcs8",
          fromBase64(keyBundle.encryption_private_key),
          { name: "ECDH", namedCurve: "P-256" },
          false,
          ["deriveBits"],
        );
        const ephemeralPublicKey = await crypto.subtle.importKey(
          "spki",
          fromBase64(payload.ephemeral_public_key),
          { name: "ECDH", namedCurve: "P-256" },
          false,
          [],
        );
        const sharedSecret = await crypto.subtle.deriveBits(
          { name: "ECDH", public: ephemeralPublicKey },
          privateKey,
          256,
        );
        const sharedMaterial = await crypto.subtle.importKey(
          "raw",
          sharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: base64ToBytes(payload.salt),
            info: new TextEncoder().encode("secure-exchange-e2ee-message-v2"),
          },
          sharedMaterial,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"],
        );
      } else {
        throw new Error("This encrypted message format is not supported.");
      }
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64ToBytes(payload.iv) },
        messageKey,
        base64ToBytes(payload.ciphertext),
      );
      const envelope = JSON.parse(new TextDecoder().decode(plaintext));
      const messageCard = document.querySelector("[data-encrypted-document-id]");
      const expectedTitle = messageCard.dataset.messageTitle;
      const expectedSenderId = Number(messageCard.dataset.senderId);
      const expectedRecipientId = Number(messageCard.dataset.recipientId);
      if (
        envelope.version !== 2 ||
        envelope.signer_certificate_serial !== metadata.signer_certificate_serial ||
        envelope.title !== expectedTitle ||
        envelope.sender_id !== expectedSenderId ||
        envelope.recipient_id !== expectedRecipientId ||
        !["application/pdf", "text/plain"].includes(envelope.content_type)
      ) {
        throw new Error("The signed message metadata is invalid.");
      }
      const contentBytes = base64ToBytes(envelope.content_base64);
      const contentHash = bytesToBase64(
        new Uint8Array(await crypto.subtle.digest("SHA-256", contentBytes)),
      );
      if (contentHash !== envelope.content_hash) {
        throw new Error("The decrypted document content does not match its signed hash.");
      }
      if (
        envelope.content_type === "application/pdf" &&
        new TextDecoder().decode(contentBytes.slice(0, 5)) !== "%PDF-"
      ) {
        throw new Error("The decrypted file is not a valid PDF document.");
      }
      const trustResponse = await fetch(
        `/api/certificates/${encodeURIComponent(envelope.signer_certificate_serial)}/trust`,
      );
      const trust = await trustResponse.json();
      if (!trustResponse.ok) throw new Error("The sender certificate could not be checked.");
      if (trust.certificate_pem !== envelope.signer_certificate_pem) {
        throw new Error("The sender certificate does not match the registered certificate.");
      }
      const signingPublicKey = await crypto.subtle.importKey(
        "spki",
        fromBase64(trust.signing_public_key),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      const signatureValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        signingPublicKey,
        base64ToBytes(envelope.signature),
        new TextEncoder().encode(JSON.stringify({
          version: 2,
          title: envelope.title,
          sender_id: envelope.sender_id,
          recipient_id: envelope.recipient_id,
          content_type: envelope.content_type,
          filename: envelope.filename,
          content_hash: envelope.content_hash,
        })),
      );
      if (!signatureValid || !trust.trusted) {
        document.getElementById("e2ee-result").hidden = false;
        document.getElementById("e2ee-verification").className = "alert alert-danger";
        document.getElementById("e2ee-verification").textContent = !signatureValid
          ? "Signature rejected. Message content remains withheld."
          : "The signature matches, but the sender certificate is not trusted or has been revoked. Message content remains withheld.";
        try {
          await submitJson(
            `/api/documents/${encodeURIComponent(encryptedDocumentId())}/decryption-result`,
            csrfToken(decryptForm),
            { verified: false },
          );
        } catch (auditError) {
          status.textContent = `Verification failed. Audit event could not be recorded: ${auditError.message}`;
          return;
        }
        status.textContent = "Verification failed.";
        return;
      }
      document.getElementById("e2ee-result").hidden = false;
      document.getElementById("e2ee-verification").className = "alert alert-success";
      document.getElementById("e2ee-verification").textContent =
        "Signature verified and sender certificate trusted. Content decrypted locally.";
      const isPdf = envelope.content_type === "application/pdf";
      const decryptedText = isPdf
        ? ""
        : new TextDecoder("utf-8", { fatal: true }).decode(contentBytes);
      document.getElementById("e2ee-content").textContent = isPdf
        ? "The signed PDF was decrypted and verified. Download it below."
        : decryptedText;
      const pdf = isPdf ? contentBytes : pdfBytes(expectedTitle, decryptedText);
      const download = document.getElementById("e2ee-download");
      download.href = URL.createObjectURL(new Blob([pdf], { type: "application/pdf" }));
      download.download = isPdf
        ? safeDownloadName(envelope.filename, "document.pdf")
        : `${safeDownloadName(expectedTitle, "message")}.pdf`;
      try {
        await submitJson(
          `/api/documents/${encodeURIComponent(encryptedDocumentId())}/decryption-result`,
          csrfToken(decryptForm),
          { verified: true },
        );
      } catch (auditError) {
        status.textContent = `Message decrypted and verified. Audit event could not be recorded: ${auditError.message}`;
        return;
      }
      status.textContent = "Message decrypted and verified.";
    } catch (error) {
      status.textContent = error.message.includes("OperationError")
        ? "Decryption failed. Check the one-time key or passphrase and try again."
        : error.message;
    } finally {
      button.disabled = false;
    }

    function encryptedDocumentId() {
      return document.querySelector("[data-encrypted-document-id]")?.dataset.encryptedDocumentId || "";
    }
  });
}
