import {
  encodeUrl as base64encode,
  decode as base64decode,
} from "./base64.mjs";

function decode(raw) {
  return base64decode(raw);
}

function encode(raw) {
  return base64encode(raw);
}

async function authenticate(requestOptions) {
  const credential = await navigator.credentials.get({
    publicKey: {
      allowCredentials: requestOptions.allowCredentials.map((c) => ({
        type: c.type,
        id: decode(c.id),
      })),
      challenge: decode(requestOptions.challenge),
      timeout: requestOptions.timeout,
      userVerification: requestOptions.userVerification,
    },
  });
  const inputEl = document.getElementById("authenticate_response");
  inputEl.value = JSON.stringify({
    id: credential.id,
    type: credential.type,
    rawId: encode(credential.rawId),
    response: {
      authenticatorData: encode(credential.response.authenticatorData),
      clientDataJSON: encode(credential.response.clientDataJSON),
      signature: encode(credential.response.signature),
      userHandle: encode(credential.response.userHandle),
    },
  });
  inputEl.parentElement.submit();
}

async function register(creationOptions) {
  const credential = await navigator.credentials.create({
    publicKey: {
      attestation: creationOptions.attestation || undefined,
      authenticatorSelection: {
        authenticatorAttachment:
          creationOptions.authenticatorSelection.authenticatorAttachment ||
          undefined,
        requireResidentKey:
          creationOptions.authenticatorSelection.requireResidentKey ||
          undefined,
        residentKey: creationOptions.authenticatorSelection.residentKey,
        userVerification:
          creationOptions.authenticatorSelection.userVerification || undefined,
      },
      challenge: decode(creationOptions.challenge),
      pubKeyCredParams: creationOptions.pubKeyCredParams.map((p) => ({
        type: p.type,
        alg: p.alg,
      })),
      rp: {
        name: creationOptions.rp.name,
      },
      timeout: creationOptions.timeout,
      user: {
        id: decode(creationOptions.user.id),
        name: creationOptions.user.name,
        displayName: creationOptions.user.displayName,
      },
    },
  });
  const inputEl = document.getElementById("register_response");
  inputEl.value = JSON.stringify({
    id: credential.id,
    type: credential.type,
    rawId: encode(credential.rawId),
    response: {
      attestationObject: encode(credential.response.attestationObject),
      clientDataJSON: encode(credential.response.clientDataJSON),
    },
  });
  inputEl.parentElement.submit();
}

function init() {
  if (!("PomeriumData" in window)) {
    return;
  }

  const requestOptions = window.PomeriumData.requestOptions;
  const authenticateButton = document.getElementById("authenticate_button");
  if (authenticateButton) {
    if (
      requestOptions.allowCredentials &&
      requestOptions.allowCredentials.length > 0
    ) {
      authenticateButton.addEventListener("click", function(evt) {
        evt.preventDefault();
        authenticate(requestOptions);
      });
    } else {
      authenticateButton.addEventListener("click", function(evt) {
        evt.preventDefault();
      });
      authenticateButton.setAttribute("disabled", "DISABLED");
    }
  }

  const creationOptions = window.PomeriumData.creationOptions;
  const registerButton = document.getElementById("register_button");
  if (registerButton) {
    registerButton.addEventListener("click", function(evt) {
      evt.preventDefault();
      register(creationOptions);
    });
  }
}

init();
