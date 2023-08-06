<!DOCTYPE html>
<html class="staticrypt-html">
    <head>
        <meta charset="utf-8" />
        <title>Protected Page</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <!-- do not cache this page -->
        <meta http-equiv="cache-control" content="max-age=0" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
        <meta http-equiv="pragma" content="no-cache" />

        <style>
            .staticrypt-hr {
                margin-top: 20px;
                margin-bottom: 20px;
                border: 0;
                border-top: 1px solid #eee;
            }

            .staticrypt-page {
                width: 360px;
                padding: 8% 0 0;
                margin: auto;
                box-sizing: border-box;
            }

            .staticrypt-form {
                position: relative;
                z-index: 1;
                background: #ffffff;
                max-width: 360px;
                margin: 0 auto 100px;
                padding: 45px;
                text-align: center;
                box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
            }

            .staticrypt-form input[type="password"] {
                outline: 0;
                background: #f2f2f2;
                width: 100%;
                border: 0;
                margin: 0 0 15px;
                padding: 15px;
                box-sizing: border-box;
                font-size: 14px;
            }

            .staticrypt-form .staticrypt-decrypt-button {
                text-transform: uppercase;
                outline: 0;
                background: #4CAF50;
                width: 100%;
                border: 0;
                padding: 15px;
                color: #ffffff;
                font-size: 14px;
                cursor: pointer;
            }

            .staticrypt-form .staticrypt-decrypt-button:hover,
            .staticrypt-form .staticrypt-decrypt-button:active,
            .staticrypt-form .staticrypt-decrypt-button:focus {
                background: #4CAF50;
                filter: brightness(92%);
            }

            .staticrypt-html {
                height: 100%;
            }

            .staticrypt-body {
                height: 100%;
                margin: 0;
            }

            .staticrypt-content {
                height: 100%;
                margin-bottom: 1em;
                background: #76B852;
                font-family: "Arial", sans-serif;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            .staticrypt-instructions {
                margin-top: -1em;
                margin-bottom: 1em;
            }

            .staticrypt-title {
                font-size: 1.5em;
            }

            label.staticrypt-remember {
                display: flex;
                align-items: center;
                margin-bottom: 1em;
            }

            .staticrypt-remember input[type="checkbox"] {
                transform: scale(1.5);
                margin-right: 1em;
            }

            .hidden {
                display: none !important;
            }

            .staticrypt-spinner-container {
                height: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .staticrypt-spinner {
                display: inline-block;
                width: 2rem;
                height: 2rem;
                vertical-align: text-bottom;
                border: 0.25em solid gray;
                border-right-color: transparent;
                border-radius: 50%;
                -webkit-animation: spinner-border 0.75s linear infinite;
                animation: spinner-border 0.75s linear infinite;
                animation-duration: 0.75s;
                animation-timing-function: linear;
                animation-delay: 0s;
                animation-iteration-count: infinite;
                animation-direction: normal;
                animation-fill-mode: none;
                animation-play-state: running;
                animation-name: spinner-border;
            }

            @keyframes spinner-border {
                100% {
                    transform: rotate(360deg);
                }
            }
        </style>
    </head>

    <body class="staticrypt-body">
        <div id="staticrypt_loading" class="staticrypt-spinner-container">
            <div class="staticrypt-spinner"></div>
        </div>

        <div id="staticrypt_content" class="staticrypt-content hidden">
            <div class="staticrypt-page">
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">Protected Page</p>
                        <p></p>
                    </div>

                    <hr class="staticrypt-hr" />

                    <form id="staticrypt-form" action="#" method="post">
                        <input
                            id="staticrypt-password"
                            type="password"
                            name="password"
                            placeholder="Password"
                            autofocus
                        />

                        <label id="staticrypt-remember-label" class="staticrypt-remember hidden">
                            <input id="staticrypt-remember" type="checkbox" name="remember" />
                            Remember me
                        </label>

                        <input type="submit" class="staticrypt-decrypt-button" value="DECRYPT" />
                    </form>
                </div>
            </div>
        </div>

        <script>
            // these variables will be filled when generating the file - the template format is 'variable_name'
            const staticryptInitiator = ((function(){
  const exports = {};
  const cryptoEngine = ((function(){
  const exports = {};
  const { subtle } = crypto;

const IV_BITS = 16 * 8;
const HEX_BITS = 4;
const ENCRYPTION_ALGO = "AES-CBC";

/**
 * Translates between utf8 encoded hexadecimal strings
 * and Uint8Array bytes.
 */
const HexEncoder = {
    /**
     * hex string -> bytes
     * @param {string} hexString
     * @returns {Uint8Array}
     */
    parse: function (hexString) {
        if (hexString.length % 2 !== 0) throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
            const byteValue = parseInt(hexString.substring(i, i + 2), 16);
            if (isNaN(byteValue)) {
                throw "Invalid hexString";
            }
            arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
    },

    /**
     * bytes -> hex string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    stringify: function (bytes) {
        const hexBytes = [];

        for (let i = 0; i < bytes.length; ++i) {
            let byteString = bytes[i].toString(16);
            if (byteString.length < 2) {
                byteString = "0" + byteString;
            }
            hexBytes.push(byteString);
        }
        return hexBytes.join("");
    },
};

/**
 * Translates between utf8 strings and Uint8Array bytes.
 */
const UTF8Encoder = {
    parse: function (str) {
        return new TextEncoder().encode(str);
    },

    stringify: function (bytes) {
        return new TextDecoder().decode(bytes);
    },
};

/**
 * Salt and encrypt a msg with a password.
 */
async function encrypt(msg, hashedPassword) {
    // Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
    const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);

    const encrypted = await subtle.encrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        UTF8Encoder.parse(msg)
    );

    // iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
    return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
}
exports.encrypt = encrypt;

/**
 * Decrypt a salted msg using a password.
 *
 * @param {string} encryptedMsg
 * @param {string} hashedPassword
 * @returns {Promise<string>}
 */
async function decrypt(encryptedMsg, hashedPassword) {
    const ivLength = IV_BITS / HEX_BITS;
    const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
    const encrypted = encryptedMsg.substring(ivLength);

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);

    const outBuffer = await subtle.decrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        HexEncoder.parse(encrypted)
    );

    return UTF8Encoder.stringify(new Uint8Array(outBuffer));
}
exports.decrypt = decrypt;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
async function hashPassword(password, salt) {
    // we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
    // iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
    let hashedPassword = await hashLegacyRound(password, salt);

    hashedPassword = await hashSecondRound(hashedPassword, salt);

    return hashThirdRound(hashedPassword, salt);
}
exports.hashPassword = hashPassword;

/**
 * This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
 * compatibility.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
function hashLegacyRound(password, salt) {
    return pbkdf2(password, salt, 1000, "SHA-1");
}
exports.hashLegacyRound = hashLegacyRound;

/**
 * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
 * remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashSecondRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
exports.hashSecondRound = hashSecondRound;

/**
 * Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
 * backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashThirdRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
exports.hashThirdRound = hashThirdRound;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @param {int} iterations
 * @param {string} hashAlgorithm
 * @returns {Promise<string>}
 */
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
    const key = await subtle.importKey("raw", UTF8Encoder.parse(password), "PBKDF2", false, ["deriveBits"]);

    const keyBytes = await subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: hashAlgorithm,
            iterations,
            salt: UTF8Encoder.parse(salt),
        },
        key,
        256
    );

    return HexEncoder.stringify(new Uint8Array(keyBytes));
}

function generateRandomSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

    return HexEncoder.stringify(new Uint8Array(bytes));
}
exports.generateRandomSalt = generateRandomSalt;

async function signMessage(hashedPassword, message) {
    const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        false,
        ["sign"]
    );
    const signature = await subtle.sign("HMAC", key, UTF8Encoder.parse(message));

    return HexEncoder.stringify(new Uint8Array(signature));
}
exports.signMessage = signMessage;

function getRandomAlphanum() {
    const possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let byteArray;
    let parsedInt;

    // Keep generating new random bytes until we get a value that falls
    // within a range that can be evenly divided by possibleCharacters.length
    do {
        byteArray = crypto.getRandomValues(new Uint8Array(1));
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray[0] & 0xff;
    } while (parsedInt >= 256 - (256 % possibleCharacters.length));

    // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
    const randomIndex = parsedInt % possibleCharacters.length;

    return possibleCharacters[randomIndex];
}

/**
 * Generate a random string of a given length.
 *
 * @param {int} length
 * @returns {string}
 */
function generateRandomString(length) {
    let randomString = "";

    for (let i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
    }

    return randomString;
}
exports.generateRandomString = generateRandomString;

  return exports;
})());
const codec = ((function(){
  const exports = {};
  /**
 * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
 *
 * @param cryptoEngine - the engine to use for encryption / decryption
 */
function init(cryptoEngine) {
    const exports = {};

    /**
     * Top-level function for encoding a message.
     * Includes password hashing, encryption, and signing.
     *
     * @param {string} msg
     * @param {string} password
     * @param {string} salt
     *
     * @returns {string} The encoded text
     */
    async function encode(msg, password, salt) {
        const hashedPassword = await cryptoEngine.hashPassword(password, salt);

        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encode = encode;

    /**
     * Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
     * we don't need to hash the password multiple times.
     *
     * @param {string} msg
     * @param {string} hashedPassword
     *
     * @returns {string} The encoded text
     */
    async function encodeWithHashedPassword(msg, hashedPassword) {
        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encodeWithHashedPassword = encodeWithHashedPassword;

    /**
     * Top-level function for decoding a message.
     * Includes signature check and decryption.
     *
     * @param {string} signedMsg
     * @param {string} hashedPassword
     * @param {string} salt
     * @param {int} backwardCompatibleAttempt
     * @param {string} originalPassword
     *
     * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
     */
    async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = await cryptoEngine.signMessage(hashedPassword, encryptedMsg);

        if (decryptedHMAC !== encryptedHMAC) {
            // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
            // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
            originalPassword = originalPassword || hashedPassword;
            if (backwardCompatibleAttempt === 0) {
                const updatedHashedPassword = await cryptoEngine.hashThirdRound(originalPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }
            if (backwardCompatibleAttempt === 1) {
                let updatedHashedPassword = await cryptoEngine.hashSecondRound(originalPassword, salt);
                updatedHashedPassword = await cryptoEngine.hashThirdRound(updatedHashedPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }

            return { success: false, message: "Signature mismatch" };
        }

        return {
            success: true,
            decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
        };
    }
    exports.decode = decode;

    return exports;
}
exports.init = init;

  return exports;
})());
const decode = codec.init(cryptoEngine).decode;

/**
 * Initialize the staticrypt module, that exposes functions callbable by the password_template.
 *
 * @param {{
 *  staticryptEncryptedMsgUniqueVariableName: string,
 *  isRememberEnabled: boolean,
 *  rememberDurationInDays: number,
 *  staticryptSaltUniqueVariableName: string,
 * }} staticryptConfig - object of data that is stored on the password_template at encryption time.
 *
 * @param {{
 *  rememberExpirationKey: string,
 *  rememberPassphraseKey: string,
 *  replaceHtmlCallback: function,
 *  clearLocalStorageCallback: function,
 * }} templateConfig - object of data that can be configured by a custom password_template.
 */
function init(staticryptConfig, templateConfig) {
    const exports = {};

    /**
     * Decrypt our encrypted page, replace the whole HTML.
     *
     * @param {string} hashedPassword
     * @returns {Promise<boolean>}
     */
    async function decryptAndReplaceHtml(hashedPassword) {
        const { staticryptEncryptedMsgUniqueVariableName, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { replaceHtmlCallback } = templateConfig;

        const result = await decode(
            staticryptEncryptedMsgUniqueVariableName,
            hashedPassword,
            staticryptSaltUniqueVariableName
        );
        if (!result.success) {
            return false;
        }
        const plainHTML = result.decoded;

        // if the user configured a callback call it, otherwise just replace the whole HTML
        if (typeof replaceHtmlCallback === "function") {
            replaceHtmlCallback(plainHTML);
        } else {
            document.write(plainHTML);
            document.close();
        }

        return true;
    }

    /**
     * Attempt to decrypt the page and replace the whole HTML.
     *
     * @param {string} password
     * @param {boolean} isRememberChecked
     *
     * @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
     *   expose more information in the future we can do it without breaking the password_template
     */
    async function handleDecryptionOfPage(password, isRememberChecked) {
        const { isRememberEnabled, rememberDurationInDays, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // decrypt and replace the whole page
        const hashedPassword = await cryptoEngine.hashPassword(password, staticryptSaltUniqueVariableName);

        const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

        if (!isDecryptionSuccessful) {
            return {
                isSuccessful: false,
                hashedPassword,
            };
        }

        // remember the hashedPassword and set its expiration if necessary
        if (isRememberEnabled && isRememberChecked) {
            window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

            // set the expiration if the duration isn't 0 (meaning no expiration)
            if (rememberDurationInDays > 0) {
                window.localStorage.setItem(
                    rememberExpirationKey,
                    (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                );
            }
        }

        return {
            isSuccessful: true,
            hashedPassword,
        };
    }
    exports.handleDecryptionOfPage = handleDecryptionOfPage;

    /**
     * Clear localstorage from staticrypt related values
     */
    function clearLocalStorage() {
        const { clearLocalStorageCallback, rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        if (typeof clearLocalStorageCallback === "function") {
            clearLocalStorageCallback();
        } else {
            localStorage.removeItem(rememberPassphraseKey);
            localStorage.removeItem(rememberExpirationKey);
        }
    }

    async function handleDecryptOnLoad() {
        let isSuccessful = await decryptOnLoadFromUrl();

        if (!isSuccessful) {
            isSuccessful = await decryptOnLoadFromRememberMe();
        }

        return { isSuccessful };
    }
    exports.handleDecryptOnLoad = handleDecryptOnLoad;

    /**
     * Clear storage if we are logging out
     *
     * @returns {boolean} - whether we logged out
     */
    function logoutIfNeeded() {
        const logoutKey = "staticrypt_logout";

        // handle logout through query param
        const queryParams = new URLSearchParams(window.location.search);
        if (queryParams.has(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        // handle logout through URL fragment
        const hash = window.location.hash.substring(1);
        if (hash.includes(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        return false;
    }

    /**
     * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
     * try to do it if needed.
     *
     * @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
     */
    async function decryptOnLoadFromRememberMe() {
        const { rememberDurationInDays } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // if we are login out, terminate
        if (logoutIfNeeded()) {
            return false;
        }

        // if there is expiration configured, check if we're not beyond the expiration
        if (rememberDurationInDays && rememberDurationInDays > 0) {
            const expiration = localStorage.getItem(rememberExpirationKey),
                isExpired = expiration && new Date().getTime() > parseInt(expiration);

            if (isExpired) {
                clearLocalStorage();
                return false;
            }
        }

        const hashedPassword = localStorage.getItem(rememberPassphraseKey);

        if (hashedPassword) {
            // try to decrypt
            const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

            // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
            // the user fill the password form again
            if (!isDecryptionSuccessful) {
                clearLocalStorage();
                return false;
            }

            return true;
        }

        return false;
    }

    function decryptOnLoadFromUrl() {
        const passwordKey = "staticrypt_pwd";

        // get the password from the query param
        const queryParams = new URLSearchParams(window.location.search);
        const hashedPasswordQuery = queryParams.get(passwordKey);

        // get the password from the url fragment
        const hashRegexMatch = window.location.hash.substring(1).match(new RegExp(passwordKey + "=(.*)"));
        const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

        const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

        if (hashedPassword) {
            return decryptAndReplaceHtml(hashedPassword);
        }

        return false;
    }

    return exports;
}
exports.init = init;

  return exports;
})());
            const templateError = "Bad password!",
                isRememberEnabled = true,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"e82b0c30a2354359a1a0ab51f527b54775cf1b1409dda6e4aefa966cb89d6f0be04e7d5f80d0d9ba92a109d9ecb4ab2aff90427385d3db5addbe6cb04280e570995dbdba43b351ab40b7954951dde2bcb8024dc2149e44316ee60e57c6445a91418adb33f92ffa1dba6ffaff0b01f6c73c2324510787f5195a3299c98dfd741d7f00386e8ae99b0a51f02f5298df6cefe3bd0c85f096883191882732a4b528b2a8bc0344fca79e9132cfd307f8e65186f9a6a3b86d184fbd8132671efd80b54b78f057046014a5186afef3ada6e35e0e37eb87b6b17b0964b77cd530afc4c9f3c02f81efc97b65824c253e5bc0170af740566dbcb4bdf0c609fe1d706a4fb15b489e7a169ec405adbec074917bae47d42259e71c628aaa5a1c16eee7cd91202e53ce684a883333fd671d026030ab8a9d35e5b3c460f62a6067920ab45812ee72a2441f02715e9b0431a6a6bf003b040f77ae7b86f0344d91f2e925a37f90445374bf3a0c8dc41f78d4b4f8a48da24ead88cacc1321f289fbcbe9636698c4f98bf85e1a46d36a80a860ce1c79574158aa4f527ac8f229151cbf4db1bbed85bb8d6419e0ab1e8e34fde8c1b4b42a3ebfdfc174067fcbc3d6d32196943678a6e8daf39b95869f1ec469bdfe9770fd9d4f80e891b4e7eb4e43230ae4702067d74ff9156aafad498dbd67ef7205af0af70ad872b4b3150b68b09196720d63effe93a00036268a94dbac12b91f826ba77dfead8c10fcdebc4f50b51d04effd3c4b98eaf3aeeb8296b85fd1255148e7353c183e0f9666191161a360564d524f19c9856c009cb6f4c1ac6bd124b7631cabf57426b4fe2c906236ff1b967022ef6662aff3bd134f57ebf0a859101efcfe24ee1f6267637e1dc9e1a3d11bf6dbb6e0fdc9f8a08f486323b4ef91b8a637bfaebd24f1181b35700781761e08f6cfe915033e7a19e7eb981547023fa4f8ec957c7dd1fe367b90a201f0affc4048db41c95eb0c59f30106b173b50fda8e3856d5d2dfa23ba340442fa63ec297c3350e744fe1a04d5a4d3bb6815d7a1184d87447b62e4afc130890589a45082ace65732b2b08bab05d53b75639b08eabab990139addf8a24c585656617f00c214c715086e8d7e7b55569e5d1d300d1b2a23341c41c0b53e164168eeb35d08cd5716796fea6b2b5df9e271eee9e7e66e66748fe8b4f1da2c3dbe34282894948a2cf235d608496591e89a80bad423adeeb2b4c6cc5557d5c781e62d5afcfcf49a5dd6cd93069dbc6e2ed55dcc32f91cbe5deb8bd52bfeaa9c64cfced133899990e05750f4716c21094d1e8d02294e474fe78e5741cf187cf26f84891160e67ff63d82b5f6639428c73d3fb16e8450c366bf98a46b79f0eae8cf2c6fb63c1a671c61034b9227fd4cb71e1fb9a5bc20669fec0b63cb7d5783397948000d39199b5a29186a4ea7a8fb73adb89cba21781ae2698adf4025b2e5230b35a7e0c3e831a8743fe50fd89ed224cc79a136e5e909b67edc523cc6c6fa8d82451fa8ffef1d169336044857d2aa00c43008eb34b8467f521021cdc84a7c87c0f705f6938c70f9d0af62ce5c7aa783d7cfd0d80b9dfb0fd4fa8686d892c9c04787d4b1026332d30b3053748e49c5aee985394b1661d57b126c087ece1d9888c7465d5c300953742be55881f8d42172712356991b8ed53014370779a947c65669f87bbe44fda9070e068e7168f2f24ab21a4ac3492fbbbfcee63823c06c3ec9444c7aa4d7adb015a520ae8275f4f18a3ab45bbe8d813d57e5858dba3f721d58cf93285f8be9c7fab86554920e9a9c52d63098dd054746887bc8e912554154aa5059e434c9b378d8e8fa093490d64695d871c0f6e2680fd2ba1bc69fd2daaf52ac1bc0fe9e1784a7156a880a4cd3fdb83b2eab32ed1a928740fd815c720316d48a5e7377c99ef92fd5626d6330692b290d96a8ecc4bb3a3589add94fc160b51f1323d64f00a3ce4ac194c4759dcf3db572defd7644e422019659d44e8334db304d5e6b894484fb02509b7488af317ac674c88eb11a0a63789e18d643bca73d92b733afea0c7df06f270c6c14d20e4e6f8eeed77b0eefe6567866d7fe9c99ba1f9dbd21bf93181b75f214a75b94020d605d6894c2eb4a3002b2cdacd2e954d7687bc811daedbf21ab166c89468caed0af15d15f7c17961247d78aec3a4edf578a7563217627979bacdbd4559393a6b69f70df77ee3f12e80deaf551a0f4201de07549a277672c2f582c1416d705126cc6108274f9179707a13ec902e273d9fd788ba40eaace705d24e348d4174caa67077d6fd4b12a9703e0a7db6e4c227b9e812cb6b6f232c930927f7ec51dd2be72868d1322bf46dc4f4158bcb85631ba11d859a12bc1b15321b5466d58b6d7e6b2928556c4056a76b29a8c6b626d8831910a80e1f54ac4620eef80b575daace8b67115b3694d12a6a240035553f488413b256683e2424999d63cb548059a9bbcafa0ad806e84456063ad4e62da7c6cbf88a40cc45f2768b2c046157216fa4132d3f52ed35283156f8d1ecfb59965e757341a4f817d88fe669b29f4c1db3af8e6b4d687ffb3fb03f8dbd6bfdae0a7fcce8f18c266ce3e54d65c35dd20015590394a701b979327b6e15e236badc12be35d9151441989a0514c2c6c932cadd47f228cd452fe7f7ac57d89912182ed68e29f8cf99f4922e2866afabc2432bd001df1b2d9f70c93b80f50a6a8c67b1ec04efaf0b4d7c6c4a921d422623cfe7be715238a5e419c43fc40b2b1a11cbca134e42eb3960d7bbd4a60a4b0af14440cc031d74772b33a630c3c2a416695ed493904cb5d240b75f4e2d44a0526b5a6f21081612948e1e6d5dfc948211b556703fe55ce58482589fe6039f25e04efa6a1dcb302e68809673b906ef36ae798b9ae146ffe3f986243b5bfbda5b2971bc002fd19f629854bb753dfe5795821fb6d244be5b30e7bc220e1de7e52aaef42c5f1032f437463717d7b0d57f43bc0ad7a3ac37f97ca2c71a10252acb82eccf739df47d123d06de56a171711d03bcff0eb71852b1a46d1397291e7184f0161546bd0eecc50f11dfc51d50fcef392f0b55d0c7b018cdaa0e5c7988e2db97f0bcdb3f63a9d34a9f90b8b13d62ede542a383df762191d3c28fa2e55e46073e1f904455484116cc0eb0ee44725db8e1b691b7e2c489008f340c41c84d9344eb55302df505d24fe47d540fbc6868ed127162563e7cb8f81a453322c2833ab7d454ada394f11c5e149f28395a8a9e4a15baf49aa09cab9e6786637c38009f70fd550a71d00986230ecc7103911160724b25e88d1fdf4c23450acdca1e59e07a935f490a4ce8a54abcbe2c9631e314e17418aceb6de7439f1e4050a14ba3af0ed31032b900ae02694af4336de70c2f00d59ff1bac61e582102092d1a15811ebe1f2a00c25364ad0c502d44a7cbd0f62ab09f34696083668107bfb93bd3a129d743286db7cea5472b2c6f87beb0df4b6992040b867f3324897626b3679113395c368b224b8cd0894fb10f4bf9db25186ca46721f17f092992a4bfa6b8451be4a8556d8a6185132af65ae1137a5aa360d8c6fc0def0c586b0b1ab69fff629916df0e320916c4deb90258a7a46f6c13d3ddb5eed4949c11f0fbf1365af30d138c1dccf7c817bba97d14eba0c126b6028016d4d2822bc7ef9ee3fe4ca15596cb2808b3cea446d52a8fd67079d965d6a4809211ea24dc219126ccbc928dfc2fcd701dd2f1dea08a1b5f4fae59886b761f83f043500d142c173eaf2465784301afc029f53007294ae581661f1621fb9944d4998ddaddf66fb40e39c8abb3f7c2357305374953bffc8c0a0c674759627fe9798bdf18e6411d009b51a36aeb2b449f4b1e97e6e85e0bf57690c1a9a8d4b2549a506401c01eb664d127f7fc9856f10ee5313ddefe59a7cd7f9aa5421f82829ec9a97725465d9a167d8a59a861802714c125973736c243fc2202a70aa04670e658e99252f79d9f2b8693d1a5be4653a16d50f3a5ca5305a3e97dad3d8dbddf3d7a3880b1000b93990271bb22c9fc94ec99fc64e341927a726caf0ef1488967b6391006baf3ce62848660c07311fae898520b65b2aad8ec26a514c3e4fedc55c470eed7a491e3c70711a7ad681623d1cc5a46adb1cb77c3e11c67f3c31159eb93b177a8e3f411f0a12036cac05352555814853325238c2eabbe8294e66b6346fa9d69f1292f4f912fd65f9e6f536d80a7f73215c7df8d5da3e0a535b0ecdb6d5e3bc0e2159509dc673469f9f93c8a9c741c63da4ce1d73b7e9c6f903fedd62f1d795d819f35c5056b84a299b45af882eadd41ca624dccb6fab16a426a8eb242d6e7c5d7e4984f7486467338caf4541a276c7ecf6d03fd3e159d49abe514f33e80c12288fd1f543c2a85046c0678dc3ef381298a2f8dc0ab66c850b5333d0ffa8063dc577169eed546d2fa754dcfeab79166dd413dd5d92b35170b6e5d7a4c0d41197d8018219466fd528028d5db66fb2a87c257b0f65ce6f6f28146b648f1ef4e1cc6a108034cc1ac6a4e1c3017c5459f00d88aedee5995621a26591181a6ce4648e431dce850a84430f6e371ae3e33192983206d7dd718b56ede5eb6252d5e9c848332a58185847539dae3189633cb52df8fb6207b3b5840f36c986c92c1321467c34ff8d01f201d93279d466c3ecb137b8ef4773f29dde750303b3b86f76a592cadf1c4750d3a180c5d2daf6322bbef62c1ba5c25038665f3f11410172aada73229eefd61823c94dc1eec02af1f2a5411a0ccded9b2063f9ae13b0077330c88c3498594f5f58be7cf6e978cbaa5eee1612f8c5a591b9fc2838c6848f18686ae16fbf7b1018a401868020ea72ce44e53a8839b52f69e09caf28043acc50e389e036064f8776786d0fcc1e09c59e31c3bce6e66203ade78d108e8294fa049f0e8ddfc30ee2580c7c6519e30ec05793ddeb042c4aa25f5cb911ac37bd1014a0cdf829ee436b428e876039f12f0b7986413e6b7802eb680a60205a6565bd5b7c2e0a55e8fc5b4d6c264772061e4d65d64d6b39ca6ad45f9c5890795a74f2b2b0f1209d38598342370524eec6f4ece93b53fda03d19dbf17d5403955f8acfb6e47e875a16863ca86981edc6d38efb402aec559ab3ca74b253d458b8edf070c84e9c2360a725142889d768f25588ae7446dbfed121b45f960c2bac00910bcf835078bf3919686dc48daae9bfe637092f3e20d155c067f0cf9ea4e9b3b8cd5b5c08a2ad7b58bd377fb61c4289a5636f490d211e2b5df2f5442d2e4990a29e9dc350b04319655d95ce613a8c6489159e328a8766e48f947d1bc3dee45896687e3a4f790dc9a53347f4e554ca8341aeaa7b792722d3756815abdaaf3e27c05fa03ad0dce58bafe3517eea5252b48870334e431274895684b93924a3f731df2e11689eb1aab45bc0bff3702fbf38a97d26d4356f494042653e7404bfc602c57d15258875adecbe020dc3585ec64f890f53db60f22f73e4a641b5b1e573bda4275671af8b8236dd0ea8573cc431233c33ebaf1b7ed4470bc9cf975092e636277a11791a15233fbc9c16d016261487027a151855cebcaaa533255e77cf7478da0eb44d09ed0b9169d0404116a9327223822820f05de7c2f478dcee1430e5143d7a1ef5438ce2134df7556db342f8401389a114c8d16097e735e6ca80fd6a785a0e7574af93587e3082735c9278b4f7e65bbfe780782014682a152da4b1d16316dc69ca2ea6fbcfc4122587b6505bdd83d0b7535c191576bafb54ae1ad521c269e6db191749675f458c655a386294e923590495c4555d1408229833a8d6cef102f71fcd9b589f3f0f0747dec8875b17f208cde4bab862817a19591495811ddd545a90d9ff744a7713b506c6ac239c1cc0ccba12a8121b214fd092f7a0e4c6a76ac38749932c8a413ae65907c6d9e3eb39be61ee431bae454ff020c20f6e47a9f81d47fb6365adb73e8331412bd06d6602f6712c29d68f4b8c96136e76d34684f11d6f975da19d94bd9c514af620b372c65703388a4337659b7d36fdbc9aebd1530207225c0a531da39f73082e7ddfb8eb47f13a0da5f956ecedfaf17ec675d774f54f319b170430b9eee241547f9ee3b972a1f6368c1631eeadae1f77ae0216b453af306d2bc7a2e3ef18299137e7ffbcbc60419ac73cf3a58bcf770b1032c8205026e3da46275294a617c83024518a8ecdc5bf25a8f6614a4aaeac9c080b3e7a922ac2d438ae9c56f3bcc6fb0e92284e4aff5696bebf03fecf6250733024b8e24ba1d828715fe2d0f8746de0746727a5b6cb6b92c3f9dae443e65bc4e36a1d73147297bb489bb56a73442d2bd17afc45de7fa1939ce881e93c40c8ce57a3accaaac9e68321356e507e4dcaf06742b717a2c6b4aa982c0caf2a109d642c75e45d8be868d7f165e44d4755fb9d3f0433d90295128723cf93d4c4cae95196d6a56ac503815a92effac364d4711320273007c17c4c1bf180169be38cd50aeed250b3500e69c88467a13587f35bcd5a45894427d7919eca5d803d1d81fb48c1afda323e16732e4ee74b4f4ae80e349e788df77383f860ce7e9a4885e32b50bd692722ba63d3f77c2d3d266c3d4d793b1881576dcf12a4299e80afee30ebef440871ec24c380477dc2a6b35f9ed17ba2a17f759456d5008e5c8592e06e915ca8856aa397258b78ee01927021b547b3197743d44abc8bdb679feab52875d3fb14cd7eb778c7bcf6b6e965e9fa9fd79d15bf5d1ebbd0860474f429a631ba2a63193af5b7de3519bd579b461cf4c5780da00123a30cd9188456e1327a9a4478f01cdfe92f435d07fbb3ba67483f9bcfa5e3e7f7c4cd0435fce8c4d3307224bdb547744b6d04255567c14d5a2ae401afd5c96ebbfe096ac8c6fb0e2bb19f1c1a2900dd0860654cd91e7d885d7667b9730ef65185e13b42c9992fbca611097a20c3573f27146093acd5ab0b0d68482ad6dfb7b3622b6ceba8dcd00ac11c95288da693744a82c93fe55d09f4e260ba4be7f853e094660c025bfb1c13eef99477aa5fae2b30a34d82d0dad3efa24107fbd59f6ca1d1f616909ef7c38ddfc7795c1ff038adcc7b53ef063fa244af5355f4c1dc01a2363413ac2df2601ea2c2ffd40a800f0a6804a5128a9bd59d5712a87a8aa1d64159d5428e80319be724a99a78e17e6381c5e02d2ee9f54f4987d724287272d5047a831828294216056c5bd83230aed1bd47a8cb4aba9bfcdcbe252e279cabc2ba8ccec1b6b7183a26cd3e9a46ef03855c1f5b78bc96f538317c9f2dd302ddbb06fb76d36eed02ed4cbbd9a9695625dfd45eec733b2d8f1ce635085bb71c7343b8e730441264b64cdc5e2e021cd58c215a0b7cc6dcccbfea7e994a87300ae88f7f148c3bad8f29e7943869e002608aab788a8032f20c1e057bba0e7e663e236e69697eb2d5e15f716f69c987562f0c204b2b5f77caf0c02b97c2d8451e5524beed6edcab78f14ba18077fb9d9342387ff5a22010a2e0acfcc3a42a3e7bd98c3e9946baa716c0542e685124396ff35a2e4d8736d5acc59446ff0f78894939de0df98e81ee686629408f530034b451a96e411ea3a823af1da7b75326559bcaf7415bb972efedf701d944c0a72c846d0db832f8ba685c4737d7040c2b4935c7608501d276d01b9f4fcf65563ab879c641c813e39490b6d54113f798be10df868058ec24aa009be232d23c2ddce55fbfab6c74615752259fcf523a045039e4de73d902c67064df3b414ce6fdd14da35e79db6bd72327a8f23de70ec7e343c4482d11bd1913ac0914bc12d241b9f3b75e8c03e7987c84cfc88910870ecaa375306c0c764d1000d949f52e9ffc17140f7062b939f016f63d785fa8298391ab00c7d1e4d3f3e6dea2c15e76e9c810fb5b4ca3e62ea9e7cdb9ffd7b3d94511e701a19fc82ec086de40f7e8c1b885f51db9444f3628d3cfed2a7b32da846e865ca8976dea38fda81741d8675d8ac5893eb3fbb793e4d6de97b368c98e49879fe33cdfcb8817d210972e29561fca43a5b066f38e14bf870f5a8eb301dc58d107792b92cd1834eafa5cf880aa515ebb62373a27ccbc02f4bb5ce04958454ddf27ee91dd7f6a962d09713fca33d059661cadde1f76ac5abbc9d9d1a521677d9ac370bdc8aa18760f8105d0d1a2a926246731a95240b4645e642177f6c9e2d6b2a3bc5ab5fb225b4578c58f38a3c29d1f51488621b40d5e030267ffd88c08c4410962b0cbc1e9436a7f0b5ae193cdaf4fe2429e14afe81cf61367048e3475759b688713915cfb3cfc75bb01bc51817309290fbaba72fefaa03d140ba987a82e3e012cbd835bd9c01626bee3daced5a438fe8f51b86e2598290c953377b35ee0a3fa6287a3a2784bfda6a93c0e36932128c65ac7504150ec63ab9778604580abacafcc5206d1783eff4f060c5b2b09f2bb4afb494c4da3e512a0b69a1d35ad99d38a8d32a56dc459894177fe240370bf6fbbb0821e823cc1035e73e9ebbe89d21a58875244f6e7c4cf9e79faf682af8c24c2e1b1147c20f39ccc7474fdb1123c86abb5501f56ce3ea9b0af1d2313c4b9739cd24dab7c3cb3c89d3d1bf15b714d78d2f39a1371ea1948343f9f7e95ebb4b521ff488e10efe05212fca5c26028b0f91cbaeb86c9dee85cf5c74dfc2c2508df9710eef1670abe69166c2161397d2cf57cd7e45568e6888efbea4608447705b4cc77711569d442eeec63c4dd360c1b86492c21f0f78baad33c35bb09c857d4c4596851ca0f6ca95a666b7d53242e911debe2a7653044c6b84476453fed17d89459d1a18f830ec025661f6c421883fe197f968471fbe89bbf0235e71ff4089e1183decfbab8a6cc6f6480c32e60131849c68998a76ee28d33b893508ff638ee24a2307b4fdbba6c9235161c8f5602c6f3d8c1cf77b6c6b7e7980c8e119920854602b2acb1478190a78a7c3f91cc105a567e1f9274e961ddd1984c9f6dfafc0e9a8733981a80217830c6478e9504a4b56465fd614d4eff41220db5d4af579df25afb9133490817c18e7cd0adb9684231d6a30e47be89cf8e256de050e068a2e36444a90fc396ea1baf0d7650250d7a17dd419d943fadf75feaa59127a6026c33fc24b1bd2c01460009c8ea2ca9ef58ca67b5f9a65473f33d8369dd4df0ee85f3c6ffea6938656f94a6fdc2bde0d9aca04a009d1d2faea6d2c2434759fca0b288ff3130cc9cacfae0eec5a37b4e128f159524112908ed70d05dc9f911d42be444eafbedbef777102383fa4e6c01a542daa69a9c25f519d6b810fd62e26fa000529a36f4646688ad50e3cb22433da6c110a57affcadcb576ef6fe7c7b88540f8710afc5e28ca5816c2b00f45dff2d72a4ae1dd8c413f76e22d71606505836de47072d891618beba658b87e5743f374f042659a092810b0d9ac65e49ee4cdd3f30d9b9f1140356b9b2b179ebe0bee1ec7016b43f0e26ce3a0e4f29d85a4474e6c15708eb12ac5a98d190df05648b3dd14db89a91751fc86b02e03e6925b40e7d1f8ca1013d5c389ab978687c0912ee770d1d2557da1ba7d4b248f8dfbda1bf9f7819ee443e805a4f5c6d864e777c42f1f09bf6931873ca1896519c334aac8a659296375634005f039e665ae3f1092e6f546b3799904f73b371321e98f3da7c3d8985871b5b74fbefdff8d2a7fefb995360513c37b458b3cd8eed842f085767c2b44bb640b5b67c90bd9d98cf1f6e1b6a86d5c462557d94511e59febf80e1cdf9761cb4096968702140774ef33bb083bc071b7dbafd188ebe179ee8d351c8529583492ef00f738263facd23ebe9987ea6a78d7ab2856453762bb8134184ba65085d3a331904f86a5ef8522c33b6c5289565b4d4701f799044420f861ba8075e8f5b6c5737d3e4b0b79cc88c2b08d12ad441ab29ac50c6ab6aa6f88671647328fec5fc20c624708214b604c8b25a723f1286948eb5552107b59df139ad9d23e5ebe64cd6b4a0addf40b0a4e4b788a5d70eb9434508baf4ca573e16b1390ad163ecfd0b21cf07ffec15bec33f27e444d56d15733783cbd8b484e5fb021b8fe1b53b64f17282c4e2a68c1abb0598d22c25b0bfe2bbf6c708a2a428e3dc49ea2ab12f78a4fa605fbb805a9307a892b367aa0cfc044683fd9b1cd6205a4e945f24e600d18d627e38f89536a8475bd58892bf4b3a6406a5fabdda92a01c86dff5dfa369d46f0690ce27dcda021833d25bcfd046b419d55e288053bc915e2d63ae213d5cb4d23c6ba423438cb69e2c8cd27aa9f02c61b0dfc15f9f19196ae4f04a3644cd852d1244736e35ecb81133b077aca92a7eede3d192c3452569e98fc5b648062bc9e16c1117cd2095e8908179f834f81b66695d68c17ef5ed4b9cefbb492d5a7dc76228aff12581157694debd6d0fbb33bcc3af65ee1762494e153bbb4b890a3be737aca54593126534a55168798774305b0d1ad00a4337dbb022e5f190aafa51be7091fa932912d5278a4a8d7bc7d37bce9dda1c496af37f505ae2592cc350f055490225678ea5928e247e8ea351323841df7d85f61a3e4cc9b6943c2db2c367f903f95602c388cb740f45c0479b2bc4f3cde8e559fdfe72366801fd7d1f197789d4e725e7900a255526d22dc3c1da486bc62cc347eaeaef30d95e935da2625567b2f3e31ef4fcd0090ea9b59686d513a5e1e5f1a9eef133df4eb8fcd57e187647881b5a3ec25344b5fa125eaf429a9122d83c2693f1b1ceec681e49a71aaf46392d60ed3186d8b2228d442b971694849afedf00569b1953d4faf9478b629e50a1d4dfb861139a12f544d8085ca464a30b58d1c5a781744b9b03536b57528cb52d55af5c470821c658fd83c6b3eba6811e228c53192fdc25992c8d8d60d8a7740781f308db734ff6c5f7999df296ed8cebacacd3b29dc1d77337c8a1f1cf48dab04c5fa12a4e3b52d01ece102062e378da7074d7c3376ed545c7ef6bbb2b1c973060e81286c3d2a7715f4cab796871ceed63a5526d36a082e43dee1c30e998543e159c47ebcf79cff9da28cf9b8258da5572bd18796090d8ebd29c7fea5fa4cb82dae52ad031bcb69866ed02a4b524b864f7cdb7341523e63980b7c12927ee4845c95ac24e0ff4aa468f1214ab2943e3925b35b5376462cfdfaedcbaf522a3e5cff5c98f23deea614952d611b0de30cd366bf0ddcae1cd651a8ec4c14ed72628bfa862b1f33a6a5f686d747c560e9e90300b58d913205aef0721c3705534820c898217bd46d290542a810a9512b210679b834c76d2629211801062c3d7f71ead8c9ebc598aab1e3146b7899b36c0f6955c7e3be257c3eba2c6a4bdf95053f839e016be8835e05876dd536a4301fdbe270673b8ae8ca6300a1e62b7b326c3c9277a9bea032042aa983055b665c42a107682e0caa2483d9073e8f996f93c66838ccf53d30addb8d2b5aba072dc2d1bbda5113508dd325c4f1eefd19c0e9b84d1ccbd1d319ce65da009b495b7065fccbbf920b8404dff00df377916da0a78a86f48f31d17e7929d93586a7730322f1058936fd86cbfaecc1d667f18b44afa482741908f674a650e651fcc0cede521d0025e4a993e50859672448c5db88d5aa9b4b26e5d85b5de1323f92672ee2a97db1a1bfe0a8bb8ff472d8ff375d0637f6420ca0233d6c700f86b5cd2b44e724b4eae110bc20328c1b4fa2b9503a5008ab1337acd5e8363373ebbcd7236bde1a98bd83a072efef5ce8973baffaebfd37af193b55de3b4f017b6e0405b331b2a97b6c6619c9be63939848017c0fc9f7e46a215194c96349e3cef102b9888f47004e5f39dc28c50a236876e50b274e9091eec7c5474ef91b7d961b77f198fc61378ce74de8a3870bc6e7ae8f0abcd299f37f72cba7f337fe5b1ff1ab685bfdc7bfef681aba04cec4577f88c4b56681107e4ced66ae784282b7183fd8d57d342feb0ba088b16a94e4fce55f7b53bd23f1f5c17300f3ad24e22df579e5dd634726c90525bfcf219f61784e1790d3145d82123ab2ef15208b301f0244c378b84a286f7742a241645fe3295bed97e493b76462a82cde7b3d1b0122649519de0c162d1e588547ca10f7b58096cb3f17c8ff1aee229081bba19c416f5c8ffef0fb3dd31ac96fc89f847a68d35444fafbe50e59f637dc9203fde2e4a957c8562064a617cdf3217d599e1f451a5347e81ee64cb1ce07eebba133ad97dc1706ae5abee6045d1d23f6e4f82c21cec058d31475d1530d2a3c487ed547601d88227c961ee6380a48bafbbaa7702e7483e483513954427d888b08b9763307769b5dd1e782dc08c109a4e8da8e961b93c447d67e1562f059f257012d54b99dd1f3eddbab0130da521341b814c0ac1fd3c6e984d434dbeb72313d73861a3342f1d858ed7fab052981b641fb259dd01a7cf01fc75f853086f91898b0d4b2e55d5d918a88563101159090c52e2e28f0828251fedc3d9a21456ba96a1d9cc685853fd3e5d1dc1278859ee4827154cfa181351d51af6e6ee6ab8089b227210ae0589fe322a42bc23dfba237933c833d0ca7cfbba89f032db7d036b4297e28c5dac421aec665a5b6d638822e992a43e90e9e1fc4678e61e4527c75933a5e28577174292c891005f1d638e47c2a0801d799c9793b0cd81a58fd959d2d8e4319351dae809b474e473269993d252c859b5c9f7a9731005104c4f79e94ceb96dcea083e0669903cdce54ec88c5092e1b7b0f9a2afadb2dc3c2327db2a35fcf0eabab2c3b58f0edf2444b474cbb71b81706a4a43857b50e7cba950b16161f0a8e6ff6d687ee8c2a8560240963621ddc5c2eda91b78cdb6f75f31629bac221aef5e72ef1c6cb57eeec4685ce83e2c5730aae66434d73c0faa6b53ce22d9b5648b578071bdca13a6906fff1f0520112b96bc5ccc97c14dfa51065c6631e98b3700ce79b616d7e47aa3433621196e70d26caaaeca8df82394f4a0a5b5cd2ae2017f22ad729d508c955eb0cc9dc260b8c6f55ea96892f9ca1f2252127de2116f063227ae5dc8c1d3f0c1db904abc6b9d51bf6cb21b8dc7966c91a5c1218d3c7ef1fa1ae636248948cfc6dfb4b50d62db7ced8c0a4161b67e36d428fcd22e2c8e34294a69c4920cb3634868e0bff41f91d4e911933d0a51e04fe7deb44e89cb7fed9c7a28a78d04812347596d464783a6540f25e9e93ee078f3d5126e0d58fb4b8436a933f8fcbbee10ae7bdffa6bff0179058ffdcb62ff365e5176f4d8d96f04a15fba9f6b0e024f6162154d843b130e393ca3dda3d8f07955a1d046ac790bc0c66828dd30b7a29bff85df29d64828e41b51a78b32ae363accfa28270cd9f6b025b6540e00aa05c0700e9971d00bc9a254c152582bd16276b2270750cbcb2130934588285613233007d7d630cf0f6059f8136479df271d67cf0f76ca7b85f98b3734272fee827874e12b96d52f7dce305027ae036175a1b60c5c7db132da38cbf4a9f40573682502b92665e316910f36470a0890c806dfe1829780b7125506ccc95967f0a49c73d92a242bfb4615bdff73ab57489ac02afe6448b90036d6b0d41b53f32c30a581353798a9c68e735b9c82035d0a99b98f3aca55c1013410b54db39a89d5679bd93321683f8c260fb4f50f77f8fccf036946bba836154887245f209f59756de86ad11bc24fefdcdcf989374c44d7ee7ed19520e5f2d345d93c4163cd56e525589e75330e1c0264df109b39daca8bb784468c45acebb8117a3ea6d1fa2ee1eee349cda7fb498d3537ebee500a2ca5dd721f9cad2cdaa2adbf73abb7a31217e1f965635ba06948632d2c8d9c41cd7681d47159e157afcfe7363251de8a09e5733dfdd4a85ecf6166f31c43d5b4628861213fd44ebfc9c9d52712c57bede43b6d836e827bd2fa646e01dec93be0b839c244335507d08f1d727d2eff4530710b43b58ea116370c903a8f927d5810cf77f9014e64c5df1645e99dec4da6247de4fefe82d24daee263f98cee790dcf26bf29b0c2695e3b4d3befa2412b727b54e45410b5b73aabafae5e9d022092935a2135e6564b3e02e8ca7f9317dc11f614e04429bdd97cca29ec7e39d425ceb8d114cb7644e23f76f1c3bc4c653fa167677b166000457ab2122959e15c31c8be510daa4d36a6536adddf61bd3d48a43112c349b9425c36b5d685612aa3b5e03d11b9c0effe9eb57d77bb78dc831298bd803cddca91fc5f6895eef38f1d229f4c9c342d40cd43e80604eecdb11eb0f316e4ec05d849c5a2a4225c206fd7ffc663ba8a8ee2438741156f804562934f9864021cd77554705cdbf18e24e9bd7d1850c6c91ee99fafff8e281e069441d82008c4277bd3f38ac52861f6003862cc841b09736d4cf5d23fe2edc21b281d1a9b04cdfd921bb13f9062d6ef5c315148f556bc28476d5725e9ba25401b41d686e0b4983feafc3fae7942e6a075cac321d03acbefc62727ee387634804b04d833423cd4a3c1e4eaafaf616cc2df56eb3e0cca862fa70c63443ce21b69ba81ab01a417bab459da9994d6ccc1e4b763920b5b0a8a62bedd28454620ecdc1b70c35ff3a0e6be8bccf73baf36a8e382d8fa33ce47b2872086de968a2fb490afcafa855f66fe9d17f796704a3b5aadc3a446d803efdd0558686dd19645ebbcfb1f2dd9372b12c6ef16b1fc4c3c852d3ecc079deeeb97ab6cd9e8264d4c7d20392fed70d3dd76d3a9426083d9bb7563d2522a1fdf30ad557e0b3c96bc49439241309b07b95644c45f7b588dcb55d8d5c6ce6fc9e5d9089668bbaad81a2064302cef402cec1718ff2a60e31dbf8c238ca82d566a27cfefd913579ce80969fd0d853ad7e0bd101ed28cb67116fb0cf176d98599c3ee961b33ee130473d6503c26fb3455fbd989af1601ade94ce4c5b4c524c1e734309b7fb3d1c70b49a73768bd0c3c04a16f2412bb020c755b193dc4d2273ddf84ae9b8c0f0191ad4b6da88973a63d5bdce05d7ab2c87a08a2cd8dadd442af749efa98f6d7d675bfd12743ead18922ad7201b27e551a681d039f61743a026dd2f58a5abd4d31fa076025b4c3b28e78ce0ac60902ce919988dbc7c030e1c24f4980487595fac01f195790fba80a50d5ba30453c78781795b45de57d1de1b7bc08b7f6485045c14f50bfc19d0eb9110071e5d85fc01ca7a0ab1a982e4a214b35844b5f4aca77c11809b01a5c8999cbad2f42ace3d95fdca89ec99dce24d7d5fee1aaf9a359d46a6ad60c812d6c37492cc2b72ec1c9e0928fec47b3f158b4ab19b21c2c002c525d9e1df80b7ead407b3abf02d7369d9604f39541bf9c3a7560e85d6c27e42e362a253dc41f6496aecd9659fe1b5dd5955d6cc21fefe3e7b50c6861eb98081d38c668f5b2d4c9b6aabd6a4ce3aa2a0bccfb3dfe8396fe3ecb5857b91c630d84ceb09ea0479b0e2fa672ab9fea688f2e6b40c06a8c3c8a1ed0105b30360531b55aad86edeaad14e169e21860e83b6313ff40108d3bffbbd7440d2470752f127cae1f923d689f997019ccae7a9e01c9a50f3b97202220804f0ef8978a6c76084bb4a27dc31180ff99c10d2aaf362eeed56f99a214b450d874283295e6edef4756e4b2e22e056eb0763b74f328eb78e4fdcebb509b71786c6e69522c8b1350d1424eb8d3c86490c1b668e0300e7c88b370392d9d3c586d00cc33a2c9e4ad5e099763d91ef91308b4dd6f50170a61197eea7aa272744155fd27e905636e188d826ee7a0af167a43d79602e3acd47b6d888798b79fc8131a7f1e4a5d091fe88ad214e9dabb40befa2377b2670a452c941965c8303f112095b6f0bb53dd2856f0b2dff23bb5548808ca17407bab01f8e8db02095ac030b340af20954cd1719ee32c75c69916792ed874b0f02e53870ee74bb5a21d4b380cd707244db793307acb04ebacf721993786c78f772e7576367611cc238251b3fad2f84e0022f57f90b484a5ec3249db6c4b9c1de766126a3f38cf6795dc4bd4443d40263cf632092d0d87bbed25136572588305fac0ac88c843845510aa2104e3bcb1dc232dd474fb923c882fce79b88ad01effd1fcb177881779902b98eafdd78f5f5804d05b29ce7e4c78f9b5f48554f2cd13b2fd515b7eb663bea0ad9c9676da83c20b8c0aebfc4a41293ca3f495640c8a9d3147aca85f89a648d1ec672b0c875350e7c92437ecc407b8e320a72ea0f3fec2039382cca26a1d6a91454ebda80deaf234314c29272e046ffb8b13b24ca59b1b879e6d09966251e8d667294a6a6a5f4edd0cb91d3c7cea0f5811cf84bcb5e67b88aad76fec95fb8db10eb777fa1f59a600350e170f0da88c8a2bfdb116bcd9e46fb2560736f9764221ddd9706f15902d45dc658dc49ed14b32dc2380eae9cd01c16dcc90ae43c205cd029a239ff84d56f6c70be65e839b75a6a0024a0b84e60e764891a5b8dadd9e5b846c9e97cfbd54696f762c56db4702034d73c251e889f68f7dcf608ac34fb1ebaceee129d7b190032ddb65be597207b4a6a83fb7ce50c712d5b220aa4a6ec4872f14179ee549c42b61f874e42f0eabe354521fb8ee1f1f34e60cf8e6be7f5e8352c42cffaa0825d0df1bddabf59c42d7b16fc1a784f574e51d482ed752337ec5e80926b321fd3d5ff18ec6dc5301677e80c49d7de1b170272c17e6268f969ae8d1b969fc27f39d447857d5c78b49b1cd8a50a4ce7c07efa12edf276668020e6e38d366b7b1f1d3d7e86b88c059ed067bd762fb285995591051d3a1d034f8d8db5686d985fb6bc54699c62423ecb33317e09835851550fc628ffb82a7e6db788888c28013dfddba95e6bf3a847a5414c1bef4387b014c83fa34dcdf0df3084864d96de69552a437ec34940047a2ba0d05c1eadb028aa8ef126442466a32d388fa6339aed9595dbb43c1b257e9e6a0fbfc57b4f0ceaf0fa5ce5e8364c667f777604b56ab34975d4580b9ec51d7a12e3374edbb81a0b97c6e39d92233c05cd95d0a5404e2c500c32763de0fc44a41f4b10ccbba25eb6aee5e9e56bba735379feeaa4d1d2b8cced6b1d68a5c6be26fb176c3f0a5818411e8661491bc41a1350434a75bb64f4f8cd5a349d1cf642941cfa3625bcc4ac08891dbc280f5814b8fffece2523133f0fd10da38baf73ad785732a56b765d91f05c7e78e0741ccf771ed01e71fcfb0b4515acca2300e0a36c423f2d2075ca872ad294836d59f7cff28c599ffe84a48f5f705353887cd5a2c8eb4aec4255417b230352d6acb0ac202a6966265aea73bfd371544f0a2a72bcc9d7eb2f192a6c8810f4b0077f3b18fd1ee6d5c0dc4ae23d0f2a36e8eeae3c721c6774247cbb56c4c148eb2e1db08d18e01b1eba3efdf4666def18886ff3ae5abac6265c9c9ad529185546e9e6920c0f5d0a88707eedd65f1df9654eb163ae15af5a05d22e50660b6b6884f2ee3442cf588e9d66dd780d942a6da9bfe8483051d6547e88230a7819a24cfcb4d37728bcbff796c315a60c7eb955d9cd4269ea43e44e9e0229462db2fdde58480fa06e13a6dc9f6b3ed6969d2887ca20dc7152cc17af0c571b90b39ffafec7534c13ff9e3e06d7f77b733b98b7067c16c08c018dbb0269ada80bd49450706053f1bf9af05d6dc68fc2256275d05084d0a11256c69052bfd6b2c46bef781418488b4e605041f2badb1c87d1c841e37476cab0a22cfb5482fe5012b121a1093d3a3c9714e017623c1a4b6fd74a2681fc7b353d3939edf2ccadebd414ffa4968737016d6a6334af1171febaabd09bbc79e560867875265532e37184f1a06a9e103ab9455406e6b726c499078da8bb6e54d4b16ce61852fe7053a2b30126aced1f542776b72c3e362c060fd3b304f23490c3a142b236a230cdc1ab8a1ccd803e5bf55264aac03ac18e7a6090003a66514709ede0271bd7d91f80faf4775b6d1d21c6556d08034229b4ac4cb55e56d207bd30dc902f865b87d7f0b27fe893a14cd5803d5ad3c01d7db7e2e9828ee4a44ae19ddcfb15344023b6ffd59de1b7cb95877c3781647d272e32ce248d95e9a046ac540c5a93daa67862c23751c3f44437b6a69aed3b75b9f8731dd78790ddf851c325d9d36d0f6239e13df3aadfd4522b8ecb10f2639b429c163102edd018fc953bdee8e78a11e0440f278987c5ba9a10120091fb40a88e4c21c940a1aada75fb5c57d944d08fac87cb6d9a290d587b8aea2602c2d0baf4968d70326b5581436fd4336ed18dde104ca5e24e0f859cba8710ea06bf81201f716a4a6edb5fb04813625f267ff651eff6013af03749758bca6a2d38d1c1679d4a9503e02984627cb0563d3c64d9bea5366d38ea4c44446981cc82d729bc25800217d9f0fde80de809f712423cdc251f3c8f84e0abb5b5dcf7787083538574047af0848ec00742062e43c51c881b73487e94db28dd9c6e3e8bbbc1cc5bb76aa79bf3a65f1a3d55863ece99f960b93521d53364a0f2b5ece3ec9ad9c9ff84786aad52896c0de828105b7cb6da503352e50826ec10c8dae360980a7d776dd20cfe4e7f573545f130e4821afe7d84f9c3c869b2cfd9ee5b1f3068380af219dc48b87005d0720cdb199c202090a01c883d662793e2cced0a029abc598aaa824b2b1f712b83d81e53b354bed36fc1ee4f21fa126f52852560fce5eae69bf4d334409829b0b9745f08dcee9d429e1cdbecea1d3be57d100bc9182ebb23ebfeb223fac54d8a9bfe855935471d95cd51d9b605480562277f4fd9dc00fcd54a08244e1f79a9456fe22a545c62267c134708eb135b66c7d7471c773237a619d53296279128e388a5540ad4acc9fc8b7312e5a3bb4c12976ea47e129bcfadc97c460c8b8aaa9629e34b017873855983b773033c08aeffdf46215a884cea0e1f4cfe8fba7224adeda88708650374a716c1d72e783dfbf93561afaa8088041ca819cf4cf46f8c0aafaf2ec8b00110d967d2d08aba58972ab5e6c859bf7ddf35509714874326b802e43f016399366d33db97c0af5d0692bcca15aa1f2ed17c4939c8b845a2e3f3c9f4ddb0c5f1838a59e0f20164f222b5e731c24a912b1bb38056a08f7cd31709d082f3aefc5258faae13bc83be8c46fbb0722610856dbba1d9d893158f8f2724a658c64d534f78cec7b01fed3b9ae999e960404323ea76120b5408ad89160dc782723c29ed5a94d3345aa66881438dcfa36162066bef31ead34961cc16e7583fa13367320894675b26085f73243cfaf982521cef2605f309e7bccbf63f8a255a268d38791966477c1b126b18810c43c4b64b35ef2d7b76c362d33d1bb71a633be5c64071d5ad94c0181f0addb684b499c23b8853b1754219f2088eb56e55e96565f7015e4e244e9786228daff0eaaf79ac3a82c7691145d8295bdf9100ec434a58e557c30b4d30cdaa768087dc212c78e1333c45de9c74fb1c702331b07fae00450a5ed470850f147ddb6cc6513b1dd68408ca43899cdf415db04563af360baab3beb4b50dbd769ab43143545e3d395074cec3eb4b2275fe6b6e87dd7d0d1638c185a3edf5ffb4eb5c38df0f51cd77f44f1134212a4d349807a983a53a06cd692321891881ecf51d4cc3bf033736ca4b60e5662baf8636fb9f6ae743f8c14fe0b21816e173b8cf2b5fb5c31695b458a60c158334523a56a06e142bfdc07fe415e12d3088722fdc18ce213b840559011c249d14e726adb28ba5938dcb862a653d527b150602fcce9d0ea577f3762d7fcaa3019f973dad99eb03c3f4b4c44a902df66c2222829fa544432ed5a0086f065d66838e52bcab95cd1d86d7affe52714381e55fac1c3f18b4a05adc607c67fd3f1b8b3b4ae7d0c2f25fb77320cad56b59a9158fed3d9066abae08411a1bcbbbb7a8b2fe39337751cb6d3b22e6f4af26838f872111c75cf81198f34b458a2c5767805e9cb68656f49bb44a2e7d6ea304785cf339c8ee2856ad54380a0683f32b29891b992e8077d1141f361b682ede2420cacb87ac56a56bbcb3696497959f5814d5ef6b194c572b930f6d22ef40fc487bdcd81f76f9b82159653a3daac728d593c14a73ff303a2d0dfba4fba3a87ffbd5ed0db598dd994ddd292100588b7c5a116c5821cfea930975d6accc63c3e44ac54d73376d704c8913138c36483c9dc1b809ed7e659a42db9a9f6e5f004b3a11dbd77a1882691ca6badb474f2fc182efc7e2f52d142be513078667c20695375d250b96b70577724038587ba4ad301aa48b53068a83e53ac287ea227096bff1a7a6700835419ca0de4e9ec4f5c6fc28fa1f6978cd7b6a1c75ca2ae869fdd323d5f7f9b7f6e868073ba2b7763bc70b7d0976c3ce90be8d274103d4dcfbec1c59e7953681bbc3fd9a4d91d9767d540dada02de685cfb5b4089ce4da2f377c4484f9cd70c3ee36972523f1e351fb47c3c2a47887e9a64bf4e38e8b83d71be85aa17c8d24d370119ebd49a406df11222677a9dc774f64eb7a9577aeb1a5c036fa90d802bdb6b2cb9b6ed459d9793c98048a26c2ce39074c2787e79549c2d4e5aa9595455cb93095e821a3e1bf18f49f0c0c2647be5b9a29c26b36f25a3a69f075f404a26479c6a08218159dbc240f557ad2642063352afbd8b74041f8fb8cd756f9be30d3e976cf976f7b252da7d6009e8976668cf33621b8e53bda142f91a4a95935d5f9338ff0c5eed85288b713d76f0e9dfe737c2fd43cecd422ba82e02efe2b944ab52d0784e4fbdf17dfb15417d505017663f3b951aa8ac7d482a5778ec86a4866a938103b87cb7abd5e6fb0b990a10dde8b8189d4e6e61b1e7c91b834326c3425750900d7f065699dc903df61b0a3ff193bb33469c990201f43a9452c6fde6ba9c5447d1aeb1548759b61462d281efe28cfcf11a7a38500b1237d028542f2c0ad0184dcca12a56168bc11b6c1f5b078892688065179ca6e9cd8c6c880f0611fdc8b3d41b441a6b390db5290706a8445de3508072c23db58f719efd995b7d2609a735ef28504a6d06f4871773dcb1d9ba7ca2506987d25afd45b32709d5de83643067fd9a0d056b42033e8c0b1a5e3a6b6f1dd31b232167901a35ca8d0836e8f54bbd216323614d528d9be03955e0f2e8c06c6bc8dcb959c2b2843a36ba79ef352cd9fc3870b21ec205ca69ecd751319ef7e3ad2e93e8c16a6ca27e704895e3d1d57a36bf6a380c12e904e96f8ef2c354e609733a28e45505baeb72a2357e6401db826a742d7223bbb6eee374600281b65e97788f65f1c912d3e7ddca886026dde9cb84bca47a80a4a27e63ad71eb4c3d77d2d5821fb58ed00205116a9381cc00cce88b998532ad400f6ea48a76287c97df36053eb401b4656941b5ca1deb3697258c23e6ba7d64acfcb3b9ed99c64655345123ee97069df6e54d195ac2cf2cc7a20eec7b3ce701840c499b0e81b67f8dd4077085b295d22cdafc6d2ce87139418f387b91ee149815b39c90872999fa1b5558efe9f00ce9a097354a8f8fdb263a8a8c46feba4edea1900cf5eb12267ce3cc622da4c68efc5483ed277ff20998bf2e4a49d1a4c8a5d4346f4297e9eccb44cdccf18f0498f53212ff3a8f95ade2f792928b299a51520c19e149a1483f79bd57530bac0915b9c22c77aa3aa1cc1fdacca8c3a459cfc1fbf07515f3bc94c7bb9523b601f71a1e2159ee95c12e81ed49e5ea61038de1f6a65200701fd1803ba319a141bfb0c76b0f7504a52cbe582ae9f2710a9db8eba9b48598ec3a76ed3e78914b91b15241f60465fae36b54a3911088765ce7cb221c5b5f1036d3e4bf0b9e89d95f24800c4d6826e42426c7dc882877166679063ba65f23888a593c90fe7e2180c784cf53bea5cff4660e2404603d85b427542b98c61f075a69ad17ca1e1908f9fb482af1bf618b49a34820edc0cb729583b2e1fc28d2b24e42952c54f00b7a7b6be7aaeaa986121c84fdacbd3ce0bf57bd93875ef1e61822ec4c8b9875254e2b00b98e3c0ada10864ecf5e5c788dc609d51b239264fbd0e6192325182a2127a9ede6eea0aefdfa32b59b91ef22af07697ec4eb1169ce0d0c66d1223043ba80dcbd1df04c8e746cb9251b56530b1d48571620fbc3bd61259f165f7ab51f6e23bc423acb6e63a47c2033263f1136440da51ed5aeb804f568e513df43d1dc25accb378672f50ef322e7e35faaf26a4775cb58e590dfc5a251bd3cbcccf5bbbccb30d2c6089327ec537bc984f81bc33578bb7279eaab954a6bdfbd4cbd2bcf48e39407ae41cd22fcb6dcc49f8e2aae29c3f9079bc51fce9bc3e6d2762558cb116e3e0d955c0180e56819fd94a9cebb019d0899f0633d73551b4f1698545747b265a789707f8bc530a107f3a612fb82e4f94fb939a0ffbae343024e420eb0ba014c4c88a1d1f677b51b61c932a2e182fa2453c277517edcc7bbb0960c3ad8fad8aa7e73dffe76abfe3258c9ed2b6262b51326ac9aa0a7bf5a672a80a31d6d7341af3e8aa0c208c7fc6975f496a17c647a72e22361334dadde15c11e685c4767ee0bd0ee11099eb58461d073709917e13325f561477bafcde5e1e00ced37d2670f76b8358901cf584614ce44d2a4fe8c56a091a06cbe616c9129e55dcd64f542db9a502ca6242d2515c9f46bf3cbb60ef3f5276d46fe3393ea24225864c9d7589d919d6d9f9b55e7cbe021b4508fd1fbde531cc05fd6f7e4467db532f6a9644840f1111330314215d26dfaee5d0749d89630f23469b7728eb173df98a0ba3e4db00e8348dbf610385898ab8a348487a283374b1ee945ab025f498c60db5506a8eee5e2bec34201a45c61b38128e35c9258ab9db77c7cb5ae107f5bc0c471f39c0e7e622dc77d940636d10883847b237e3c0a6784a196d5bef9dcb7e30b75e892a0b5fde1123fde3fafaeed4c6408c47d5f4d0d7e986debc815ddbe3948eb4dacadb6f305a804991ee019487879946e1af7561836a02e263a266072f25cbd73588e5cd7afc73df1594872d5fa41de74805c20f7905756b546576531a0533dc3f6e7c2db3ffd752248c5126137d21bc312cfcfa1a19d49a957d9908156a4bccc19f197c1e2bdf1edc3fa42463e7f08623f3294fba772ab1d52a28109262cd717b197b926e5388af80a5962f00ac5454b248d3dfa96cf6da86e672cf6a0843cbce4f68bcd0cafe4a4a8163a7b85c3833c155c8bee45925376ec7c58cba2f3d61d8f6025d5cd2c4a0e7a8599596b03167a1fb454f9cd49b2d68ac8f2542c52c2c95dee5112d60b2ea0a002db73e8c81f5beaaa60e17ba78bf91457fef7360537bc3f69695f401f441dc164313afffed650a126f2ae8ffdff35054a8e7b6733f79653ae0f4edcb3d39205ddb5fe28c0dc5c555e1aee7787b1c8dbb7b78f3bc5df647d4b758aba376db24fd86c181d8c97870ca16b0a55adba8d63c5642517434da0cf2fa1348f739818f50f7272a852c094361c1aa127c9193861b355467da295db143cd306ffaf5a1994465fa1d680c0ea41c8b829874902e9347b6fe5b05bcbb783c0fdfb35451073b2b0be268cf5cac9181442a86e561711353f3dace4a06ddcbfbf7e46987e733eecbe102fc09f4f2e04e0d62d0a491be0d32a8faa3113026085a01da7e1e16842a321cd80e8285bf825ebf715f4a4079c44fb42f1af2b0993a33acb2e72341cb58b15a871dc8e26bdce82ab7fbeba9b378af092f7f104bf1fc196274ead9490fd9306b39d8690c0224440c2cebf16d497f4e3fed0639c898a0e145a7918d55cfc5311eeb8b9c1074a0550b24b1dbe17561d6429536bdce9bae8c6dd5d0504c6b326bff4ceabb4a7b4ffd01259fe35d972fab23836efdacae9f64666a3d63ad03588b4299fdda2329f9240932084f38e8b2ec2eeaeb415492294b17a83b0bf77cac92add224a5b943d6a8b5ea362e1b82de39d9e0c0f8e1bb3718b8e69e229d791107918f70e861d876e77520f63dd49de1475400d7df99b92e0f3246333fa2f0a96d3203c3b2a1627c6fb7d421e8df3b55fc31878dd6904adbb08272c33c7f2d4fd4d6dce34b2d3c7f9ee6af51fd57c5c1b36ab4448c3524fe4c78f48282489315a15cd09f4b2def3c1b6f9838f5524107a9b77d4724b17ef841cf6eb9bf67100ad4c8bb7259ab20c9a6f8a9c04a1bfb7c86f1ee1e93c74b1ebcee69f9816233ba5f66cf8aec6008b7288f7f041033c8a55cdcd5f0e5a6c39aee9040afcba8e47b4f5b5079a18cd8f170ec70b8cf77bd7ba89979356bb39d844ef60e7a6d4c99d67c12c6935f37fd40cff11ab63321aa527c09794ac97bde20c9d243ee665803411e36a2b957474fe251adb72bbb279c4e49c0aeb2fb22610b9a691b83f9280bb2ed1f917e6d4877356f7741406aa63d1dd3b3266bbffad160c99f8daf9946625ab06d2d9323c0bf48940b808ac9865af4068fdc8d2727c9a12f34ba8bbb2165839dd025d42451f805bd0a40a3186a833138f81f797c9b36a760387d116fe8cc3700ab97e3bbee31a130259a1ed1ff1ac8c47a22bd8fb4b8d8d13afc9085d29d8715112b48f879bbc3a5cc99dd55840789cb29fb4e180424674d85ce4456189294f37c410e3f6c215a7a645a60b83d977f3e6838345fcc5b18800e82f08304e408bfbf10ba8aa6ca5e6119ef2671cf567328a67820ff5bd3afdfe0c80bc4cccab1193b4370928599831c60e517641959bebb9ba3d45fb7463c66328f186877cd9ba3b545f550c9236d42ae24abf6b36376b72b7d1950169f9ca630cd04e2d7c73cb133c8ec31197b4d01a5bc3cad385b7d1b3b2ffe3db520cc81343581fd34eea9adf2a3ac1b5b80f01ddd5776e2686d970d270266eee11d03279094d4770c15699736da70cead5a41a340d486844dfb536a79c181ee7604886461b51dae4000e8c13752d58b1ba72c84cbde7f4329d988fc29a547940167c459673c30e141d4bacfd5cbd2fcbde9dda95224308c16e13e98560ed7b3c0e86090cef32ce1415a56afe924ef62c7b35eb45868c704a1bea25c85ffe0138a1ffba79846286619d94111e000fc3a3eb972782b8a98661ba79adba042771855a499faf53d4bba2359934685fc5b84a9786fca913e795c5a518f04c10ce2d385ae4417b691cfcd076a5a57bf5f3fdfd62d788e2a832fb6bd97952c7d6e10ae3759078e4995f7b354ee3260b35ed088b34621d9dfa993cc7f733e8d9b1d47649db9f2d2cd86d4926060121fb688f1a33fb7349881fd410725117e4a3f06c105940c852df847d762b0f6b38fee6f1cb7a9860ce6b3fa890160f37112f8512f103b3027adee1e36d5ebd3178a7d6b36471eda87f4b05d247fa4c2fcfd35d4e9f0cd137f978d25313fab4b1823b00937d3d859bae6834d8f086320713e5e15338663ff84ba31b3389d934abc760f2435c96483c362f7d2f91b3eb8401c4560256517985144c44ab1bb9d0a0b81d2ac92c582ca9568c924547c4a29a4e16622d52e4f1b4b18c2fd410a651411c6146bacad33fc9c3f0d3d7d9a2656e02d3be46097bc2120e047b5b208775dca4bc53b9331e059a53e6119edbfbc0373f09e6c8d9115ab836c52925b014372ac2bc9d4c1ee6744bed4136d42b7a58cd93a7377954daf82da1463a03bf6c9eafa34bb86f0294c614ba16296b60bb0e577f7b3e78f3cde3fa0423b6d5fb65d0082fde2367beb3d3d7739d774480d36494a41151f3917a5aa86481cb8f72d3cf232210f1971921e0f505837b1cc89a905f141fae023c2ac6580f5c130158c5ba2bb31d16e6d40038c430a15cda0aad646d38270e3afbfe11ba51bb21c6972ad975430c8f26d11d2626a05856e70cbba94579bf6fded896511a776f19d0c0254ca4d61cf7daa267050dc9c4af9192491f5f97c0852b49185240f69d3abd77ffe5b6ce0fd73df70eb7ca936146fe4323e35b32c6f96fa2b4ff96c3585c8f02424ef02eff79bcca94d9f7ed653b7d9f1a95a2ffdad78ce4c24f84568eb18bc9c08eea8d2ee21abbcb10219740e56eb8b1e01da780e79531bc4665c23694905ff5d6d4d50a570cc9e46296024650227cd9111afa73702a06f4cd8c6a4b12390035ed826f3686f7c7b81e1cd456222319d950573e9f71edbcc8dee7415532daccc84df68d702eb0cf2bcbda1a4b8ecc233d3f7caa9e302e847f1cca2a5c75f2f3b656293e94995b379920930401d2f1523764f419dfd7ff9f89f08882b66955fb14fc65e8595eb4b29a77fb14e3937e4eacb22f1eb879ae9cf11a593969dc2d1b7e18f434f2fb6e3b12b4863b9339f99f47adf248a7de9b8d28091641f783484c4fe45fe931bd26580ed4151be982e4e7b3089eaa9cc0cc111f150a90b95cbffa844757c96a3b7e6a7e86c23265bedc672b25992269a1c65cac1b2a6c82bd1c39b02f5dcb8dc3bcfa8868943578d8f727d9b07be161a4ff720d97dd2def3c088613e1309b36ed649079fff835a205f03ee366c468d97bb101241a6031b0f50579321745ebfd25d911abce7a56c368c3324e34151cc8809f8b986b8de84231873b7f1e9be5ac80428e8a112ebdf6aee67e8903cb13557cce7fbf6f65368eb0d3c81cf7216a960d414fe3dd13984bf4fc7b5446975e5e971587f12979a6475ea80221a0679b898f3e2724a430eb6028b7aeb821b828b4efcfd732ac60929e93f26cbd57e5cb66f16c70ec0e6711a962066745a62e3fbbcd9fa0cf189c293ee9c4329f920af5563bd585571814ffc1f108e24381fa65c8af01c768f9919985e049c4b33d58650fd2ca5451d05c13fdf1cdedf92423eec8c957e91310cbcf6a1f3ff311eea5b3ef094ce578d6009e81134dba90a3a11e999029a18a7624f8b8194029d2a1ab8d3a59b885089f1b3d39347f302ba52e50a65c2571d5fe29af9c5db6604fd1330db063844fe3bd46a2afa21af02aa6474fa3456ee0dfaf08c725da4164fcd26bb496f4540415950bf7c83abdc66f7b4856ba8b3818a3f71605cf75470bed9b58db87bf45b619a9ac1e7225bfb1400deef5e882b9f87405012c8dc816062b1f84fe3a0730a292d604677297babb103cb55b972048610ad3bd2d7884c1a35a5edfbbd2b9d34ea276c19948b6664f42340d24280a83e8375546a5eab7b414510738afbbbb0f108228024f8609b0bb0770c53049b3e212a11718f94482e2529dba4589cb2a506c3670dc7b8a9db5b7b76743002ea48163bdbcbe877e7e226d717c3b318eaf6bf5f96e53377cfc9bd1e5f9e0a0649f38c3ab254d081434d883b336945f83c4c0234fb7412fc6419266ca6c3e31d756b08499cf726093ce06ca47d84221dde94d9474b4b61c7772ff14a30c805c1783be669a5b1ac40f18b678fafd15bd6ffa48e1cb3430c5d4fb12e793a7e85713e7a8a05a0377a97e31d4b283a30dc510e2d56633f1b74da6ef5fbd565264abb6cc8de1d5e951ff439cdfad1caba5e10a560cc5b07096d96a4f344f1663058ac792b94db0668329aaa9b987ffe0d60eff37c6b7dbcf162f55641991f7570dec59f151439e4ffade19bb518fdd72bdbd96ec6aeb78e51705ccef1db2a338fb4a3e593271189c61a2829f3993ba12165f2b8e350130f6cf628a8da4904711e67dce9d211b79120c3396ffe47fff3049b22d4f314ad1e7a5204af796b030f632feec1d0c5d5069162f55f32161368c273112f2f67886d5118c4a37cd51b0fa476e2b5950b920b4f2293488e90a14bbf3549c3325e09f290bbf0c67223c8fd5697d9980df9964894c4d46373297b5d7fb77e44d2481f1002056137f46f692b8ddd62655686d8d1a9001068af25539f28e8bcdb8a8c87f7c3ab7b5191f9e63e34730cdd0b3a016bf18b76ef6d427aa167852090cdb8ebe184beda0a8c96bbada72f51d82e4f830ffac33ca57dca13606c01ddcc397e34b2c8cdcdc345e07307aaa454d2c17c35c9962f062a4c12b1baddf107a56aaf48ac881832bec9aacb98e8e5848e3a2f3f99ba7356ca2d73d041394b012ca7f8a7bac14c521337420e2daeed7a9ea5d2cad5aefc99d6a0a37f527dcc605a255874cb804f79e4211842d68091bfb2351805dccb2354e07f3b67f380fdff27ae4d089bcbe8bfe1deb078198d9abd5ec998644f96eeaa9d21e3a3104efc9efcaf7a3ebcf870b62e3e3de1dc96279d4323444961bfc994a78ea159dd225f556a0b623f8710dc0e969d3bc695e2819d41b2ef5ecec0127d5e42c7821f4cd1cf0fe93b2879098cf3581c0bd9fec7e86392823ab8ad64cc699ff0a433b139210340fe0c008814e3e78358a4b03f0ebb3830d086b6039c1fabe94db01c5c67149fc8dda86b9dd47d720b5f452fa3cae9b87953236586851f4a8ad2fb7a78fd527bc320d86d24aa8af9863fda6b85caa2d1a45a97755dc5e2330d2b0d25c36d74e71311d22e985b2df55b80954299a3e488b91ee2bceb32042fd9b3b6d9fbe26a1b0b36299d751cdc69e4c28e3254f3d7447bf07167483c8a04f036dc74ba5494cc9e3f040de0234ce1780181c6dc261a8cff11337b2d415b1fc46ebb0d8044e15096aa90490da84ed9c9de48a0616727c9e57bf1929144a9f0ecef131c30677e4b4e8ffa7305cd36ea2b87cfa0f1eb33157d98bb7404bc54b10121ec13e9bb2ef738e980f2282d402d6910a6f8e91badc80cb4b509ca2433f8cf6031b7158c9426c9a7ca259afbfdbbac74a6410650aaa349e6ae27631f563f7b074835f11abb1169f6b8061bf9c06baa0a86d4be7d52c22e4ee3548edc12f55e4c2088cac586b9cbbff780190fa92e43f3cf6774d82bfb2a7e368e6195d2bf4730fd3d7cc042655cdae3a042bb473583ee95ba44fda5b220627243847a9f88c83761626d17ce9277cf1b98ade89a489118835c4ec181e564045133bdbda748dcfeef9c25ceea113ed585b233bee98d730acb3f57f2c611aa3a63a1e7b5339576c0ef3f47e6b85a12e10ff29f1b76857f75e2aff121cc6ee9be82da182e52f4a445406487b9c160823dadf95ccb3f7885e0ffcbbcf510b727cef2009ad828d9263bbd4753e0dbe5f2f9ea1cd4d19d65141b985fb3f83f2a8713f2cdab111cd6cc5b87bc8a742a4258854723c8fa214bf4685763689f54bcb984b8973b3d5d4cff8588f127c555cb8ffa3413d271a930dfcf67c9c3660ba3c66ec911bf4108fa1f5dcfe9a3518dfae9b217026a27612ac20ba840ba10f4a6023ebaf11271db51a941bff748fd65f07b4004619db864ff6bbaa371874118d25780187c5b877c6a1558b30d138f5e4832dd86a3b9d9d2b6068398bf0fccf558b8a9f02857e37c4233cb230ef97562ea2cfd9bc6c0d998894037aa2aa471ef38332ab6db8282b03447bfe217ef96ea55fe6a909142c316c1e013779b4f553ae5b48be9119faf3601e827c5efef50e3316b8b69ea46bada8b4918f0119b45ee0ffb4540e1666acda4b8bc829ee3a2b39534b0390bdd073fd301aff6935e3fa7ec27f386cdc2c367806797871c35d82b991336c77188cc5a8ed4d179bd4722cc6688c09314122b26c0b584bf7e9aa54abd18ffad0451466d9cebbb087e267a7262177a67ac141f2c66bf44b6b9506576cad26a9d95a5aa9c07df2cf0cbc7dffeb5bee2c3415812c0846792a3824e72a7b4bc9dbcc455cf7f3c9d2c08096fcef541d1187f24fde5847ace1b2614593c18076c090c574ffdcbc9dabb1461dfb66a86f78b0f8894b0261cc54515c5f430fe37d10f3177c5122785da538c6610e5648eb16b79fdd12ce8d57c1aef612d0cb16b2fef46fbb8963ebbf4e430f70e49d1f4b949ab6611ace27667850fbe8797c664a49861f8708b6918bfc657256a53d014d7c293e649b20d39248e5fccbc32b2acf8634569bea4c51c578e654a2b56b547b7c122707bf04f9fa1e4e67f0f2620229d346f8a709ef2366aa95675cd4d73e84c14a06a82838bd135847e7f171fd9c2be77e89cbdc1c2c47fe5f21c9cb39e725ae9c0b79c178a9bc30c71f298982d1aae71da9bcfdf973a5f7c6bdf87807266dc26916a266950907a68ae3f3cd67790f1c0b6b023f6c61c31a2059ce5a28661f8f474a2c84f71fb0825f96c7bfa4180a9b63960138c6f958bb956e56bb8a951b207933432a0a84d3e1c79233eb6a1c5ff1154d6527ae8b8818067f6c2aebd35e75e5654b3d5562aa8fed673ffcc37286df8199047ecba29bbc9570c0bf2f15672abaeb27cda9a245078a74180bcb73332b96a2b081bf4132e88a7ee1deaf697aeb38b5b1344bf72eb689580c42a68ec84aab75ca3eba9c527538bd2c2dd5c66a557fa80bd7bdd2dec69a9b4714f3900e2ad8d3e61096ec6f5c5820beaa48220d50a6924c918783f720b4e686193500233f23dfedacc4ba60f3e8a54dbbd6cccc9a9b4099f9cb6e160e6f7e5f386b06d7e4af650c1fcb7b8692468dac3b7b3e59a2acd76b7b210cc85e259277dd095dd23e6b1ce242ee5b70f2a08286bb40ace3d805ec82b394deeb8dc024c7987632f6aa9755ffc391307ac33bba728eaac3c2c63e194dc150ff29485f6ec398a5640d43bc6c1f394e0162011be4606802b18142ea86b2639010ee1b17bbcf5501dc7083b49373488aedbbbee3eb40657833748cc3b3864e2bac3ac8498ba11c0cc55f037a40984f14d98cc366b316eb845079f25a3e4816b237f1524621842184925873191f603c9ff8c11915dd793ae46e23e8b77f4e77a38f71b367c29821716df106e38f5f6487f0c03bf707df6b2b213add47e0cb5dc3951d3ff7a7fab19912c0b70a1ad4b75aa9accd2137e6f6d6133da998b05639de23669a6b8d8636e6a5dd932332872ae6fdce4c1a954bc072c9dec62517a660e53ca1b0b5c187a46a62490820f637d2c2599c7ab9255d4183700b9fcecb243d888fbd414acb17f7a6bfa8cef51260217802480cb8048ae547e76e7b1ee6839fcefbcea245d7e03a354f85692ac8edd5895acdd9b1835b3dbd6173496247cd7fe63dfc99426588982373b6c8ac0d68b02e8bedc269fa1ce374318aff638e6cff7e3e9750cbc0fd29c7eaf7fb50f777293f3340d93664ea4cca82a6f892bd2b0fe8b0732535f394959adce3fb97b47f494507bcd924b9d903269a01c1ddaffc69fc7780f6eb02fc2e92574375c392bfa6c872816aaf5890800364e978a77e26b2f0368e76177cc3fc64a4a878ebc643090d9d1e4ac15c226f20d37a994538a45e6c8956688b6af0de66295b3742ee08d78f23b3699d5c1d6c168fa83b1fa4af23edaa0eb031c3f5adc095a080551e93d373e52730a02c362b431a86b69d7a0deb2e603886e23a0300dfaeac468a6670b65e8e6ea0feee46bc4c5f56771ea427b3447d4abedf818e96504cbcc084d141364d51d484d0230861d440ec671b09cb9a18811415281527a3ed8ee85090a1ab67f0604b0c31cf411ed736fd0cf0c490d8e8653b7abacf876f2e44a5cf3a4ee43318dfb9c523746ed41f7659580d26492df066c01fafd0078d5e9f45c4f9b07daf72900fd7287084f6cc45c1283164142e05fcb76c434488e3d1b814f9275dadca2e0b96590f4de828ca6190b31e2e5e9e51a292ba57f2fd7469b621451ed2362176786f475fb0955023f30a09af4283f42db4932c11172466a6dac6e73b1040586a83a772b224cd254f11520219f4dbf0d39f772a625ce2c67a2968502689a4d0ed419744e971e1886cf108db41a78f3739614e32d7599961d912569dcf35da1109124643ec398c2e9ce9dbe330ef3aa226bdadb954c13274d5f5a2fe5e06c6e7c9411c5da1b8a0e1f8b4065a103bbf9ca48944e1461208a81d2e89514fdc0b8b12b1ac13c0c8083b10a3746c985fbdf418eddd9383a4d6c5cd0a7ea8529d6542625ca92d96845cecfdd2dc0a48fef2bcbcdec121dfbd7c459eb082556d24607469fd1dc2753aadcc0ae6c3bc74ef80841f41ff75ce624b04d9790b51082272d7e69b2e2522701268a662188e56cd7e0f748ba6a142d29009cdbe62763299981a2bc63f8cfc7aeb132d0b0ca7df2fcf5dc59c46fd744e666e1d9e8cbf2d1b590f3573e8c59da8e06720c246792a6a6c362f2bff9f8bb478b5b8cdfdc986eb1dd6374bb6d0f182d0e5dcf3811c0290d1948db98908f20486c91a77c7c0cb3668e3e6dff78b19ec7ec09b81aaed328600a7b3f260ac6cbf3dc4e3c3c332108e70dbeca33311b4a379bcb9cf98248a860e2ca5bedab2d56ea89afdedc999c11a76e603970f36b39d40f8527c643b5ba3f7a6cb46be9a91a8768225c33087b15219c3e492d22d3e6ce7a759dd38529b2c2f660cde74e72c88a4e6fbf2705580fdccb6d1d3f4804d913048cd7bca081599cefbac139bcdd0c5aefd097a9fd4575cca86427f4bd5c75353d202c23aa26c899528c47ccf84d99d310ae86b76b504a6ef9ec637fd3c1d3643f6b9025291c5fea311ac08d1d48e0e67a2c62a9d1cee41c5331b4fd0c0ed0c38d8e5029b5f3b8475d6a5bc66a3cc3a1c1d0e8c6ce987a857b3e0f0cf354f598db4f2435ac092e7b3006dad23e08e56c8107a011cabec2792c74cf078802c03e9d8641dbbf95a35981ae9af4d338c20ea1b0d4c159442916bdc942bd44eac3f02ba3918e35b739ce1b159ab0432551a12fe1a87a3a6dd5ef363f468abb292b19298f9002b2e330641a875fe8531adb885694daf66dfca2e64be74eb50b0554752294ce0d0c40171902772caf72ecc505ed9381339fc493d8ba323c783d7879d8448f9a4eb6eb626428b36d305a83c3a60dc6d80781df2abd3184cc6baa46a289f75883689ab4bfd38ef5fbfcaf760ea94ed69910788dc81806b4d7688ac88b0116c8d1867651859fd6a91c41c603578a0a64a1b430b54b2453606e08855f65f329e2d8425c779d73ef2e4ea6a0ab7a54091316c6561be35716fe96ebf5b6cc48939826946176e5fc56d524a2b3c4f6202e58121c45176cff1469dce1d9f3961aa3aa21c8e47b18468c76d689b05c98e7080e486b5b450d2c0f38e286967e40f2757cf8eeec2b6c84abc27c45c1019061a3d9d6ccdacbc2edf6602c7c3288d1427a0b67e7c042e68c79cd828234a2da81e60d3bb9108ac90346616b08f242889268a255bbae333eba0ff7fd6e370c6150c322443ea5df0cfb81a594428cd906af1bfc71135feddace2b5f197bc778dc24741ec2ddf22f89b5835020b2beed967f1832ce0c2c2cca87447b97a8d3453bf11ae2be9bee030096cf0f212a8cab87f7bfad03f840da9b93e72b2d6184e44ed416c78b6a5a71e36b0a4a4443d7fa90799373e525aadd09da247c6f379baa8ba44d0ff891f25808c995c4116fd21bbb235b0b2085a42581ee7c900529208c9754165218b7ef6c568bc441c6ee1e0d9fb24545b190ccc43c4e37d80a677fb933f22a7c667cc6d4f6f5a514c92e602786a2b93513b6e118efcdcc4dec98957a047d15d66f2d0f0d58d90c4c8acf7e9e5c237e8e3b7772f1741db9bb8ed8e4672b0736a933a2a8a3d4975cd31dd8ffb743523da270afb02d092d44618c4dc7ac1f2ff572c5286ccdd64d67ccc5d8df205ba0a37c3d4f51c4164f28028c98d2957862966b17dfc850e4a324c6ed8ef33a4de6971bae2b2789dbce278868bfb92cd78f211deb51f572d02dce89e860e38ca219ede72fcc9a122c74b3883a283a5aa66f3dae5fe4911e616321114611f36f08008eb1ed3e9f69f0e826e8dea28919d69eba5e0bfc692c4b37313cb0b3e836190c96f3f0b5227786abfeb0a0d8bb756682e04d13438e69bb4167140e6890d9d8166c42f472ceaf5504aec11d3b06831bda6765a27044eb503d651c1540862b469e0effbe08a958c16020cc817d8f87f1cec6e537534600ffcca856a8e61b7b85ecf521047a05fa8860746423efa55446ed6e9f62a195561f4c520736bf00dedf5dc4f7ccbcc333e86d7c48de3670723786b77159e50f4628d5bd7589cfb5c6ff04d6955111da46c782c02ba9a5cd6062f67e2116e21f915248de9f05e4c0364caa820a49e3cde8fcca13b048bdaacffcb6a7a41774b0ad24501958c5dbf2d4d78f8eb92e24133210b544b82061a506f093a1b5d31350b3d99e671264246ef826acfe95d48b2999df6783a169c1af34a9558ba77e6b72f0354533d6a41de95c9fd83dd46f5b3289d3479a16f1ac4873000b5ef70b9c549a4e7199e67d068dc9f51c7886128639c931889fcf4d32b23546bed7a10b5be364d8ed82a7f68fe445e359ac6a0ab9f84e362c917d2236f46f3c73c61020a3f697c08c48daa015cc9c7299741bbd869a46b3624d6bbb862acc62025779a0067c56831cbbd2d3e15833bfe85a8535f2cfe7f289d616fb1c29764455929567a5206310cefd984ddf5ecfa3816b9545275cb4bbb834f253fa9fb0045e90284a1c700d927e07c09be5924f7cf5bd42fa608ef278a496c104d1a7dd322770420cf7bcc44c0e8ee503177a04a94e841fc4c3b2f2e5f315a1c9162fc282212010da0c8f3fc3ca4a82b46632f6914345d109c07569a9fdbffd147fc0fc5cbc6cb766b2b8c1e99cc058626c1c09652b43558d11179f474e23949f18a4950504c1cecd9971c08397991b33fbcea96fe0e1447cd4cec6112806c37357030cdca1bc1fbf3457cc3e258b0a769570075e1d8614d568f1655e5dcc34230d4584dc0a32db41eee0105863225d11a1cb96608c0e0f67340ddcf11a62693228cd76b7d6ac4034142c5cf2b07588a340fa5869c7478adabf72a359bdb0b08c7825f75082e022e497305b7313466b6fb2179cfbb336059d46eedee3ce15d6813a521c1096d531f8ceb521ac83cefa75104b894c9946bcfb99c6a16a25b9e8f76970dfb38d953b359e16f20984e8f7a80d95c2aabfa1433f7ef9b201f44fe90ab3e22928aa530ea5bd344033e2f005de38a854c8a9a030d9e33dbbaf091e741c3f27687c03a88a272621778d31c22c577149494be2753e88d2a6b26801bb97c94c89ef2a16cb28be1adcc4a0e897214a00a0632febb30386d1cb1c95c789878913b6c4226b42215f10720725fc80bd9abaea832a222786bc2c9af7ef81a430347500d2a928b379cb0a984b0c5836bc782a8173a18c27a05ffb97b0aa673b375c531cb0347f5b27f1e54103060c9e107c7d13a03e70e27a4bd8ee4f04b686d446991b2e771d454b9bbcf9f0aa788ab7a0d496a41ac8fca54563139b400c82f8f3b01be9d1c8d69501ee9f887776159788b8757b7fc9980f1acf0fb932bcec5c794f3f22504d3fdc5b336ec8532620123f2eb8e0b96d46fdddf1e1ea4767f05b5c102d1d436eebae4d427d51fe2772da607a4e9e9940aeca42b4c9511c268e4bf090a8b83a8a1f1a90ef97d8437bd4a8fab92c4c2354be8447060817ed66af7655c21e4d42b91c701b9268729e88d23768c62bd790316da1106ee570db86f2315f1b16f1ec709e790eb32161233a2008fd1166f33f1affb4f57cab5de8cae5d5b66cd28b64a6ecea2b114f9c2265d4798fc66b5e5c93093e4619ff80f0d68406eba928d5d70da9654b87391835b840c391609be8797e81fd2f3939c7dabe069205161bab6eb67f714fa4613c5f4582620f5ebc0679cfb5807fcb88830d47caa8ffcecb977c00e099d68a562860be146ead8ce340bdee6bbd9e09d054a9f3e72db7b124c64ad328f23ab8c5294506ac9eecc3755afa830dff9f35f9b7ff952428f14bd2ad6b4cc034cf5e4faaf2028a6f073dbf4deecaa6de83e608afe9e99bfa2d3235afb10b28a3866c4e58b10ff445154e613302dae48d1698d15f3ef3f5e9f83f0dbb421babc9eb8a098fc79b34a7abeb2344f74c82fa4767c5c37db38d3e2e2ffa3c4e496b8c2a547602eb60670802a1b6366d0dec4062b2cab1247a25d59f42d320885c62576784fe323e98577c3ee72bcada99a6ac1e1a425c198b6d796ad0a635a23e827da5932428b0a2665ed8fc07ccbf0ef69d4b40baf5e6ee927eb7d80df022b315fd1f381dcd651846afdf4ece05e3497d169e28df6fe7ae1a63538e2a6a0a0676d8c038ee16ead2f904dea8f8ceeeb5bc855d651f530d8a7dd874c5cd2a41b669b6e6f886328d428c17acf56974fabc6e46ae5d8955d69f8adfc670a29208a01ab456683b0903b7ca2b0a60e29cb8f25b56fbeb5793126aba376fd52cbfbcce29e9bd8662c4814df5f761d2a79360bb87ab3cf046c21a64c99e992173223d7fd26ef806100e1d3015deb3cd64ac366d2a57ea3b1f96cac0accafb92ac9e32331abebd48b25c42cc8f573eeede073f4aeb74477f1b0704ff8255619778c0d04e70a417e9986d95693b05850c9b1b6bbbf37406d063c760a4d1b1afe0d5507562e37e4de21cb7966b3251c677ea9d7254e3f43df13259d4e85086c40d74a8db8d4a3b72673021353b9b37e55dc774ce5a1edcf6c960180ce90a7454908b79023ddfa03c60d31f96048393041dd6ed75f9ea104cce8fe2722a8850f4fe50390749ad5639ae655ac3e674c70ae134cdf768b1aea13a0ad99e19ca503051b3dca02050efb614c9b8789a2d290dd75c167a93536098f9de0736bbc53be1a386136a9aac8b13673b6828a362ba29f04b6881a2bdc9ef535c0cea3e2e2fbed313bd21010e67a4f59aaec39febadd925c15ec8e57cd22dbfa24efb1f332b4e51a095e392840ea475d3a65c5c5660774021174b84617ca4e5cf19192217b32f3f74af087a70bf146dccdcafa2dff3ff9afe553bc3aaa37fc9e4eafdc34614eb9cb6fc1f3fedca78a6c1c6a1b47e25cef9cbdf0bc6681da235964eebfe751133075712450efe3dff3a4681d3027c2dda653237e67a1a39379552a28ed2963a44f2a9c427ad09d556b7cd15789f092b0f596565a0fc44fbc70ac40463a8f58b68cdb9a926886ac50d0c0a603c79963c360583e44268a2f0ab4a36c48b170158cee33646cc68172ac72db9e675e3b8581adff127ab32b1510c6744e9c311eec8df63b02b954373ead990eafe632a5164637f9014702f2e103dc3b068ef7c70c12f84225f2803f05db1f34211f825e93d016283c370e523797163a32ee0a2945726dca9cd0bc452ca9df4421a551c2497f3f48c8064cffe19a3fc5b9500b4929481f5b2ea696afded239693abce4a723d26c018f9a995b7804a7a8ae95867688f2478d87bb4652e452164c10aeaa66a572c7cd81983ddb8008bbf46a6dbf56d02300d8253972d45e24bf11029ddaaf9800eb8400158d12236f0528cab21908341e5125b7c2969eeb42625310a0fd89cf7cba02d778008ee69a48ecba8893f05ef0a5aebbea6eacc74f8e521e61df5d4b4985b35375ea4e3da49bed43ddb69d1510525ccead42daebbeb2800174f983abc330cc2c62dc9c772146e2158f9c8c223644985caf54a1be90c708a993fe7821ad2bad3abd6b535a122ce5ccc875f89453cb848b08b9bd71c6935872f2fd1097d9a3b9fca23ad25f1373b50a03f0afc04adcf168ecfb32c031d241e041af8f062fb1c9a4d9cf263ee85ca12da7c97ae3ba2dee4c9afa9beb06c1f871ebd71f2bdaad8e8cdae981dd1fe0a3fceeda520619dba09bdbb7c5001d2ed725d11c3909986edf79789d003bada184d6718223b024212d73d02b56ebea0069e326b2b469cf76c8e57c2f8e9b67fb5b21e2ffa2a99d253625c893110b02a815bd7fd588c75823bd30f19e33bf9c49c678a4f7107606db0de7105ec71f9bd9679b887c6c70f6b142b1ea1e4de8d9e03424444332a28cc52a2b74fcdaa303c996ecbee962c4b1dbbf85eb76b75aba637bf468086bea876d8700e904a9b65f2c20b1040d3758afe8b06c0f2ee45386f34dd8ed64b4d4045e8918e9e9ae8d4a4e700e93c15b2854f03ae25191db744c5d8667512cd931280dc8b5bd35679ee40c36cda5addd192efdaa1247e10f1e77c1a234271e09bf128bef56073f9a5f90b17ecdab9efe36e7ab6b0c001332b91504ce6cc8ce3920b0901d6d4e56c945d9fe9478bdb74325da13a98758cbb5379ca372ffe4c586828d733683ac25102e611bf75303505663332b908e08ce98b4e1ef4fcd82133f076bfde49be04c1580108d0625d3dc75689c18b3508fd7799d0597722878236113913a568186b93fee9646b29915c18792ff85bd9962283c11dc46ce00cedb50a2960797fcaf7fcd0e7f00b7be461ff25ed958b015dc023807fc3cc3ff0e2317beaca69e22810b340ca17c81c108d32a27ae86fcdd0404cced9c688126954cbf3ff270d352825eb8b00d709966bcf0db116072a39471fcfd7555a62c12a9db1f21d3b5ea6d9cc37f6b73c88bdd5a719e936e3f168258598b4c76e3a667ebb0127db09a64429d63ef356b4708762194d31e84871ca44b5a0b7f52ec9a8818fdedb54c70deee16939bd348a307795eaf752415039586a9aeb86fa68995330113eaebf99e1e9a5fbb5f55feabc70f876225bd7cd649bb7b56f87c024208f4b36ba84dfc59233897134b430c8e6d98a6cd5a9b2b0e3a182a4a3321237e3b754e08243824be20a28410adf2b27182653b363fb699a044a87a6b5abb54752e260510ac934304799994f7e914cf9da96123fa5038425f637d6e3f2c8a446639e8b992dbf978c3dcf65d465bf70691a7fdfbf1c7529076c446194ea28620c578a91839ce3be2c5789266ab31c11d5976ed1cf6cb37490f28f71acf23394678b49a6e1a8ec2d97a95d0ce329e300a077cb9c16a7c7dc070047114b30feed44f50f82583f6037201beb62ef47cd5cfd41857d8ca76d1745b91b63f37bbd2b8757219061068cb7d9b14d932638dcde0d3fd74cd811abba52e65f0f2cf4e12adfd13c24b7567818adeda8d945d39db777f88cf123963d6f2486915ed9b7e5254ec11f2d2ccadffc2ba16f2a4d4e588474f98932adb47a84345d14a32b3b388ed16142a1b3dd6f46b5d9346c107f14fc30019b12ba7f5a0cab4cced1229628a588dd8677621ae33d1eee9d847c1dd7d841c0e1528e54155a85803a8bb3b3e6b90ff24833947bd49ff09a2fbc80e30489fa155e3febff4bc2af6c0a6411e83a8f59ce97a3b040e08995587699c94b2b268945842936afdb1e994ff6643f88b5f753ef1e4337f0091614b71213204ca6dab269d502867b8d59f42f1379271ca5e45f40635a0d4a6b36836f336971d5684f80a6916f2707237d17babe05c803fb4870cc839bdd3812e69db1004d8da9ad7b528af68bd35b25f9a15365770fcdd86aabfb403df9f6129a41a46f38ebe9cab76c3b74733ddc09217814eeaeb3ede8fbc1690313093f0722ed5b68ba9abe42955e20f23aa3be170f9801eeb560dbec1fd0f28b87ed9489ac003990e3ec48dfa2c49024b05f80ed2465e1e4c34da3b5e475f8c8625924c71265f7d48d37707f72ae27077f36a9ba2f736199cfdbcdfe6722df8e72e8da66674a32cc553a19542b4ccd7fd8f8a9d31c93daa3d73335feef3c46ba7836e20d0c2a7b3f25583e0143abf3071b5da5212a86419a533b9e4d012efbb8fdc49a5be66c4de76497cb84a1308a5d223fd5414af5e997fa0221e7fbdfa3acfe271b50a3ce130ac9dc012a8d74237896901e2df54a0a0df02de3ea2afe7502c903c3d7f00bbd6aba34305f0ad040217c453ffcac2c3b38da3b1938c0ddeb76079003e4a6ce3af3605f8a24a5946a8e6ec1b78e248e301ac48fdbb4c82d9f60e67c4b2f92ffb4cf5b06370796c2d129c419b62bee5781322604303f9920f1738df43f93e901a11b535e742513efba56b18fdfd991b42aef36be9cb3dd682375b3ab33d5e0e3b52742c3c1109ab290108359e9c1c5a22eac8ade1ecbcf8082b5b584680d41c74239895db9e657f0ba711a053893cd82e587a075d22b20189a078a34dcdb708031e9b9a9615a7d1c36bc1571794a679bd23efda7dafe49b0e275928172cdf5296b24fbd3e2f8020c9c34f1dfa9e1dcbb6428fb8ae0a53c48c8bf9bb9c0bee6b2f598c95213269cd2066c10f3227e78bf5e24f5ef5cf1c3b97d19c98febfbbbc1a175ad866e5df1eb2b39d040d2685ece5f8556d1668b264ae57d041d4d2fef06c51c84ba8779ebcf325cfa9051e488d0f353849ef79365d91a669b461179e1f4895366a5dd8af72ea79ea831d1262a08ad0d3adf89e372ad2ddc9c278bfcd069f97cdcc2033d85708680bf457d4a8182515f9f84d29eabbfe271d36d27073f7aa371cfc861045b78ac2942c1a92b48a63d06f79dfe1f1f75e053582a52d6ae4701ae1cf071ad902b1d8333d2a1a88edee7921282c044f6b98d023843674e51138a2a523653d65f452be881d87622205b0a2dcd8ba66e9e0b707a92b2a977d1671409468547fd64a9950592eb8db57088da9f821f3b1171e1c4d49e3d2d0932ca0ca558e6717af1a169545001b3c0fad8899c9181dd90d974f0e1bf65940845f1b1eac3bddbae2833adf9a65be711566efabd95180eebcebc383e45f15e45d41ce45c06b3b824946135dcb80d8d66aaafba2b3d931c336623aed9ffb4550185f8ab9d0220f20d6ccf6fcf067552dcbd6cb0f18c16756659d17804b29d378136cc10db3ebb146d42014ec01982ae42a8b8c360f38a5f6064700ee935c09d956ee6dfb910d70fa8ffcf4120a82e9eaa74bd50d350e66be74eba7cdb70685a1fe904a11c548d5fda4ca41b3a597474bd6e8908d1be37f5ac54b5d8a3043caf3ad133bc969b34d69f1be81096369a0015af73bc677df9f8dc6e75bde4b3ace68140f0ac156b59c9ed900f11d17c081de3506d11905d66fb7b44bb36448ae64d8d8bf4aaef5a173301bbe7e36de1d1084bb2bea7f8897ae8a26dc8eea8849a926b033c04276aefcbaae8c8a57545d1c11744109e49e3636b24bd629329165947e8cf0963eb9062526e2c3955e49349f17f696111cb1303c2965cb0c3ea58ac6fc976035b909352120521367ec8e1fca095954bb0e979deb578432ab65fe44ad458ba72fc64e8c3fe7bdb9936229b5e0f2456fe470f2c5254c27e2f53e4b56e866fe807f16fde7c254c3c0f3e74ed1f4726c380759fd655e21b9515e5baf1baeed497cc7a8ff9775a5baf2593a473ced416365ba3cb590100c0ec2f5a4d0c9bb758cbae026aaf8b5e9ef4c3e74cc2774270a6b56973a5363d313a91083d6c35144f8f6a57963764c2262adb69f30893b806930b834d9d1eba4fc449ea3d35333fb732225f24fc4013781103f126fc8787bec28a7bc0e2aba823f4c988059683fa5cad73afa1758c79f9b5838b68d787b4ae22b63eeb6cc9a8aed1468a924c29a2dbc09e220e0f58f30e83a9b9c9681bfba8033f4f53581839118e41dd7588283666ce1fd829d5c2ffbe9d49eef4ab16f74131757873d1008369e5ed71eb87ebc5f6bfbe0bb0ab6c08b226d3f94e7e85029b6a7983f9c9edd57291447f3ad6a46c67d2a02f6ac49885fb576c8b9080ca6b750886247945918b75356ec17a5dfbe6aefb25b7fc03cdf84c1205565ae9af861be7ce7f4c38d01ee588fc28b330c37b4b986a7883d7dbceeaf4601aa64322fe6afa7ff67c4861063516696b492b8313f2354fe0a36305bbdc5a0867950153a4982f9d71b59ffd07725480d8d058113bedfacec4c57014a460eaf21a4d481b4a7251acc1b1132afa758fa8a678915e8a882ce9ad4173698af180252085e60d344c5f5a8eaa50e1d9ce6e86c3eef67a35c7347f12855e805a759d35cd1fab97f8b7cd300cb67e038f73f91c0fb370677595308d2bcf18aff4906042df0fd3c53b5e4ab2dee60406e96a38526642b39a564429d7d314d07a5178914ea25e553d82e8ca78ea9e9deb132227b551e1397c9ad9f83f01df47fd5a75e5468202b65daf8183a8d17d2a1f6bd0949f5767a7bbe2451e57536122faa328cc6d9773aa9e289db564563500b154a6e8ab94c439e19130dc7e661fc1d57b59a3fc74184bd8640a1bdc60b6d52386c69c58dc2f055dfe0006a8e3b552df21076a644ef932d3aeb774991909f9b97eddaa1679d1abc90f32dd4a9ae3128f05fe66f54b31d309669ee6c0e5a7ef725fce3de04846ddf27232586edddf5c5f53f3a4e1dffea5d61f2cf04210f6e113510e884576df21a4d848b48c604058ca45f2bdd08e2dc8622f7ebf5f8f0dcba593ea005c1dc5bf8e20bb2f3c477f3cc91ba814015b0373c1dd3e3ae71f8e5df4cc02f42ccd315c1fa66c791b159e27b4aa7ba992015528cb3d772e5f8b114c368c97c488c9fc4496f8b13c462b9e30ac2bb967c2a0220b20f3e5636459b00513ccc40a4a4f87076e826e5b2a0c5fe373941d74b6b7d1f332926773aa74a29de2efb79e7a1a49c07483e97b9359d9f541e149da0e8b26f5b03c425aaf99456fc680e8fe4c1b17a88caa62915b573a2f5315498295414c0fa928528abf442e3b43d70ebf51d1f09599e2289bd9c9a3a5e49398bbc2de68e1976cfc445a7b042729233ab3f44dc6e726488de35e96c47cc4fe9e73b1034911ff96c8696d85e9e44b5250c30206d537335a03bb6cd4a348b01102688446936d87dfee26e94bdd10e57bdcb739e02a50d1a64adf2fcd5b21a3d990a6322deaad87521b87ba876748e9891725d2f88bebd74c262add0c882fca1ec7811b489021c720e99640e059cff611cff59b2c491c248a9b6d50635328ada23da9071864149d844a9aa3f6f33309adff98838114153a3c30e31d5f5760230e281b76c29130e4d31c3b6b4078c151c340799077ffe52fbc87b40d2f03bb4c7b486fb88dd22b6959aa82f3f8d0b756d34902cc19ee1c76ecb1816ba80998bf370399acef1c031ce63478b9426f0ecfb994b1d7820f9714565dc2f06194744f5e4b33d5877aecdb06389b2badb923920df9d2271283d00816c1748ac9dced54c1903224f829d4a5d8cfe64fa5ae83bdc194736c576b642c198caf75e4c04a0ec00e0b725c080cf66f8061dd9790cfe2bf0782b8442f0ca96dbef29e899f27cc7a889ddd945eedee7227f3771138b45d8d81a29037b96d833e844dcc5276ef604737278e2df53096a2a56ebd5fcce54f3b893284ab81bbc7392019a30b428d56ed41d3774bc6b7425d433644ade11ecd7ede4acf372ca794e064ec483bfbd2904d085767e3aefacef89a5e6817231ddf3dcbf7100f69f7e2dedd0d3dd514770f70c26e31ef0dd8070ca79d94a97b7067ca759ab99e790cc5158b6e237672205cc3951e02988da7c384b750c617f522fea3f182877b177ba97f2cd8d57907da1e0497260c08cef61f8ea6e36b041133074790ad07cded2d2504a216a195a4d3f95cf60d23752dac0a4d32291af5e893666e29d20b5f25f71fa51da42dde25f63b8bd1bd0296d9607b08f841f35ff546a5cf44958299cdeb7f353cfe748d1e6d814cdda48e225b51cfbad5a89eaec5181fb16437dab341316359b0c36b256a8027bfc6ab684e4981000278ace126bd427b5555b444a98bb97a9e95c65f9d3aaafb85ef48154e8dcab61652021deca68828eb84069b91e6ea42bb22b86ec25be03b441ed45c9ca9153952e44e9692eb616e9244460ff7113b44e6ec09f48320db3972046f9ce6bcc04d020045708bf001360cbc9d1bbf3df9dfa769572c1702821a20bd85a02dee3b9513ccdb1c1be293ba528363487c481f37aff571fc27ea6f9092896270eac124bfbae6a82d3c08a4b2eaa2e2be1656ee9cdab3c2cd417625ba7c5ee55de75ccc2e361fe423b05aadb206259e4104e885344dd0298b9ea3d8d7c44faf7c58ce0746c158c68847d992307c548ef5635e27e17c0e9034eb28819357be1deda21adc3dadc18fa7b8eea1c6254f8be3b4b9e09478e177bf76359b18bb9911bc50707b859c7c8d16bfe0275e4e01a54747afd399181c0966d5eb8d82df599b704e2cba205ea699c2d3d460a3bc4f60338a647f35e34189ef2bcde5b3e0ccbdf550ae94d865c446783da535db4d461932737a95ef3e4b5df6e991d23b3c43b46ede74051be314470259a690e29567fe92812c52ff860250d8887c77a78adc4aab2f9081d8db884c7f6b7fe4a42bb47842d877f43ad091db154d021296fb01082ab207b6d39c90e3b28e8e0033c9556a426c6c18cdb0da25742972d6348e38b56604cd0b62aa811e1f6128371032d505b1183c2daf8180438b46da1e7d121cc177c0bbe2b42c7e8fc1bcd68a2ab91505b7e24df97056f7404c77a851680ea648b4744412b959928044c950696586f5e3cefddae0b8931cadd8a44a3d391f064a2278c8f52dcd622892c4b6ed9aa21b1465dfece804efa68311f4d7ad5697b3137210dfdb7c633ccb013edeb55cfb75d83055b58d4bdc76702fdbb0cca647ee0644aa274195bebd4469927020b126cde00df6daa33203911c9af73e1138ee5d70f44c7ab5fb7505b1ab0264d40c7fde7baff149598fbbc0041315eaa0800f0fa76027215249885d079292d7dfd284d1498ee0fa9ae1b460ffc54d19fd41cae3b93472d6e42f5942dcc01355e37fd61b2498d67dea5c16ac6e3528626711b517b370ecbb7b74555dfde6deef9bfe21e0b2a5069a888ee69eb7692a05ba3f8fe8c5d835ce3378f508e3caac4a841ba2a12b569414471db848fb9c01320f17464399edac2ff26f32d08f73b1ec8cd14efa601e2758b3ff1c5e621f8e8f8b4f63b4e3d8d0a5f6a59342761b2ab3277eb07772e32fe72e2d165cc74b9ad702e6064de62f493683e41542fd843ad5b957b2d3bf6d89a338af88e11e54aaf0a05c0a3e9fdeeada23d99c645e0f680aafef7b7c40b95a38dfa2ab7abe50af4c849eeafa53a20c38461c9c832be284a3268e3c270d6c813657b8fe343266eac88d6fa46826db01eb7968add0262716ee5457d81980996e28fef520742c5430947fc4f88c77be33a5fdd0ccec44919651f0d73bd37e1738592c0e29c684882028dd82a67247f6bac0ba11baf4e7e12b7be02b12495de1da5c2ddca000439277bd0d8ce85ddf45f01299c4e6bc5ba276c861301563e2b0366c7468f03881ebbf54b73e3e0c28e0e8a94c955449581a0cb6f88deabd77bfc58c7e840d71a12160adf454215b1aed02a79c70217d1ed01232ac20030fa77f8d075ba7fa71fe4c6618d63598b6a15c651eaccceecff741e8ab224cc67eb97cf31153155cbd00c5889766dd3a6fd7444292d0c7d53ebd278c7c2ed695564a22de4ca4ec3b8fd6c710f5503b879a560f9d9edb1a951d884c5e40519790ecf4734d39e04306d69adebb66321d2e95e1ea3190283c80edd065e237ca72e99168c4031cc31d39fd655cf63bebc79da1943943a8afc9cb21467bd4ef392d571f78007f31819013b861a947a4ed17a048cde110b803d096b6b74d61cfadeadb91adc7a4dd066a2b2626f08609e7d468c410b2dad723b679b338ebe36e61087756ace6cdfb598610e1f36a6838cad66ffd2f9b98e4eb20ddc89067b6eb58fde3edf0f58721fd0fed193641de36b69534ccebb8d7599a35462d565f1274d958c6c23d8cfeb34162bb3dc7c10a612e8ce1e0c2080693f3edcf8b8bee7f211b4dbcea57b34341650f955b03538cde727d573f25a9e99a0a4d142f1076b79cf11d1ff6c47b57ba21e4e61714d56f5f02a1b714d90e5d97ed256a683826d781e2377e15e4e6f1a53ed27f1815b33b32448c4c68ef5f1f163261f4673dbde080d054517dc2d5d4aa1f305c4e6336385ea8164e27942b33d640c968ba0fb520d59c66548aaffc96a4653b27435f807ece236883ef3f372f621396568709c7e0871b3db32645c5e0f9d3db9a71d8fb2ca8b45f775c41da1916909d329468b14a7c1ecc04172fbda44f90fafe533f67b3f03a1f253681cf6deed16269eaa45aa141521f3f6e09330b9f83c6c6336ba8fe021651be522ebc9474e8a75e67c33e257e504d54c058e446c2691d9fda1d7c7fc1c491ee0c284cb5dc3277f985e7eea18db79856f02b92ec3e8d78cfb36aa1bc7062b1f2aac4d2071383372c22d5dc2f8fb6c5b8934f0725d531b8acaec08f50c661594343de519ebe0359cc80059bce42268338fc61bd0e39acd5ac31b5def7684d232743d3d21678952a8620c4862f8bd91460b79b48a5196d532ba4553e4d8012a7fc312d7edcf50d1b1e1422ff506d7dd4ed90558b38ddacbcc8b228759a55836b020c6c282ba713a007841daee64ff7e3cf5efd9bc66d74a7368ed87241e90494d8bccca63086a615696108ef49b9c1be87434587ad427bacd54dfe95b9577eda0f517ee5cf5665ddcb47c49bc7c87b6fece7ed1ba2a042561f930da270e26406dd33dd03ece4ef773b1e69e384d374c39abd368b0a4d417566164edd8a60fae8760e1458401c34f9055e1ff933e950c570b265abb687f1cfd7f4bf7d4267109ed8d38689eca4fd1b521a1003782d9dc92c1ebbdf46b4e76785b0399fe82c63a574d348d5b8e704529c27ca6066b9af902a43c8d2dce94a7edb3eb6b3055ebd3cf89548e7220329af52269af2dab4fb7c4e879ccab98fa04517043e1c8d6278a218e962661fa8e09e83def51c7d041036374f762e1b33ddcfb3d67b157bcd7ae7d1ebb0e84549d1434f8747e1cc4be6f02c15ed51d4150b7f055e5c71db8704b3047dda7dc4f6ab67cf1b9f6c3e4ebe02dc24b1b443e9c8219d17a91f0350264dcd2cc930f30bb91ec1cd742aa1a3284e448bd46140175951d67cbb192a99cebe4c0160a1bd349c75351b2d0619de9c5874ca732b80903b7f4e297efa4b78308df9841d9f42bd62748081939e1f6b3b84037e4427c9a3bdf2b9efe5564c17d04a6e14b87b3eaf36a2cf4f5cb2f0edc6c8d16cec6d4a12973efe23e49e1e269ae8d0a6462e912915b5f5987809f8f16a5de095b3d356cf6cce4fd08d8522826058266a7da87ddf8bc65317c7ac3cc55ac29832eccb13e19349069f6ee27570ae33f70b1c382bd6b0186f977f52e454e3f888ae0f31b6df0b065d37035a4eef641bf35e199a06024d7d90343c8b5f52dd3dd8495318d1b90d72710f86f4129a9525f55be3a113b8e95d59870afd576c709f2824aaf5fa67e09c8c86feccdd5ab8108dbd3adf5a37a9cf6343ae3affd9ea5cffef832765863a2ac6ecd71604a753b08d3c1f256cb271b22a8a887b239eb45b90527d216d18688efb9bdf32a458c21079753ad3c6ccb71fd91126baa307780a8a3e0d3ccc3c45280aadb5f727f89df8fd655acdc19a7391e90724beb72f108eea2200e7e8b8d3aa708f54e2d383aac94dbd91a6acfc1edf56d3c6b84a6a2f94a4480114b4e3089e79528df31f7e7115bedfe62c4a9fc7b95c652243ca3a88c7b6b6d8bb260451ff5b1ddb0ed475facad831c31a8e914c084945c863c1ea099c6d3677fa0836f75fcd370164a3c94df825978f47f7e3f0ddfafab42f224aae14b483b22305e154aa9df3001ea3a2362713431b2c9b061130a781493646524347839dd5bb70861c7b6cace73a171ec08f9ea5104db2a2bb20eff6808f3376b814c3d09022469aba0e6ab93ba6153a7e55fca8b2dd25ff5266b6946a6d1722799d03e67e11e4f0c245df8615798289f7e88309b3000afdc43449eb09a2f1b9a20017a6d904174b2145995d09b697b540dc27859fd613f3c5433063ac1b5263df214605363793a11e2066fbd96d8e19327742f9bc598658bae5927ce25f08e499475446a233a819fcd7c536766e7b7542c87007e2ca761206aa55d7d3045389b5a162b2acb360f93964f77924a55b1408d30b4a7964287b929a3851ed17d3a222c44e23e36da4f814927c9845846eb9aeb17ff81139b0becf225788e6844cde956ba9cd8bd6f7375675e338764587a12b3409fc438c30f659e9f6c476cb2d460ff9c7d97820b00e0c6aba9912a2f0b5cd78ab2d2ca3b7ed14473a07a3f66269f4a205b60bfea245a44982d15e69c2e87cc090903f58d3e22c5f9ddbca31792c205caf2bb29ba75f2a1cf7e1b6ad252a7a99d6cc33e1bb85b552f54e97cd6d8a7ee3b4afcebc21fff096c19eeebdfb3715738c563ca83f02f6997eccd71cf2911d0238bffe6e4ad3ddf3dd08ca6f3b6bf6a7339f355aa5a8333991b714d5e2db04da8a1eb4b62f849b1801d0031e84ebc0f99191de591ca3de2c6b90a76a05bab40a13bcb3299b3840534869dad66ee9c1a7ac82eec770d58252f9b2ef54f3977889a29e3a0ec4a26fb06f78cfd56a71f90125bf27778cafb7a0060d0f49092a6af64fa3683339c18554f54d2b3320a4dfb2a46fa22c4373b430907530e36fc788ad217981a2cf496f82be5aebfa719bd010d3585e175b137663fe4a61438257b231b70f741aa9881a046aa6f34fc185bee6a41bd95bde7749203f2bc2f1c9887a2e9cac2ee0c024db2ad90c5c796c9d6a7643aeafb2fc49a5ab1879909b3c5590d0a52d87302db71aac773a567fd9abe46132a8878b9accb118015fa2d1375749801600c712bbf45adc825db4757a1c3f2f7fe506a8fc365d3a84774a1bd48ee9a0d7d8ca1fadd1ac496f71869d6c690ee2444387319c336d17f3958cba1793e0896028505e47084c6d7b66d18f2d7af14f7ba64226f74ce1f8c2ed8db015a99c3352779b388d67ecdb47e1ac2e0df8aa0bdbb14e578ad55b8471ca80ea4d0e8881f8e9ee2a2c77b823de585a2b1ee576d794c248d1f68f0b9c7ed91ac01690bf804d9218e7551103ac20e511731717c64bead5ea9727d2161dc7d7741af2c6d6db84917ee5a9d0f3735f515b6ccd48d72c66b442aaac111a0eda71906c47d30dcc7f8f3ae4c540665a5f35d2504a6647c20da097b6713d1588ec0ff443264e62c0420e0cb04c0a272eebb8ae8d707ca897ada8ad7bb10285694e7be00614103e8852d3a5165d5e7c3da627ab94cc501273aebd3802fa303c6239fb54782a8dd556141a26f5f172ea43945748f9694ba6a9e8e835228a8948ed5f66760592553278bc4a8637f637cdacc892c7ee4122a45fb9ef6004a5e6da4442858bf65997a99f3b3c4950de0a721f4dac9c8d2844053a429faaac4e4740b37952baa4d942c0ca8c6de143c3b68876c50638469f11ea7d4d4d6b219da01405e946376c7251f74e52a0428a8746b5580c4e4340bad65c80d6f191b5aa67fac759fc6d026607f348c89da999d67334f95c1dcbfce1e2ab214ba0a99d00385dd5fb2cd99d64fdce15fe86fa278bf20ee8b7a810cc3160669c87b172fa85d28e0243fde64108326928a207505c6e3eb37342215dd798387dd4d7192fdfc89acea99d2112a8b30ec1f6f31d7ccf18dcf2984bce066be17a10807f191c9dd7e0f81237dd2c025cca9152f18e91f87c6af70c7c3084920d44d2150eff901259438c2cd59f7addb0e0db43f262ca8bcefce610a844124849207063eda6d7ddcf3b57f6583860bb367ba06db08fbaadbac92ee291604f4b5d8884d88b0462ac1596eb86c5104c1cb8b4b00049b378b286da9248cbedd3e97ed841d8a1f8d9e4c347175fdf0fba11930d64256cd7ce2723c5e7574f23b356024e9c7c974b34cf449e220aa9634753433902d672f80e1d37fdca7f0719ff844d92f4e6362dd2be63b74c298d2448ecfed19aa949dc9542130e4bbfd9d69d32a45af4d2b5d44fb27506bf8770560083c9028d71ee1864ebf43c6e9cbd4b668c85a599e209f902128e80e5ae5bec656efc0d7e4d5dcb4f992965ca004baf737da79139e19f292997a9a14bf8a87f97a117107e8e34693d7de81c84826c6015bd4e359b6bf3f5ca65380c058be3484a092f9e01f4750e0d2fce723cf1ac8a9a8ba4c83bc5b928a646fbb647a4f109b2f819a6c81c042c3ff5046a2d12e26c924d6a19141ef2c8bf1eb2e58b190a496a4db6242e24b364d537950b2b441fc8a90ff61c60fe2080a2763e20c18a9814c9402b21d97346e04aa9134c3f5031e01815d4e1141dd63cd0a547fd64a385dd3924a4c11eddea1a1548107f1d33acc2423c567477ff5dc85e1a65c202013b87e65ed910efc430f42cc80dad6d3934dea2719ef1f86ed4a6d40b69cc9d48dddc59c491f109525254f30c7548e46af85b41426d876cf085b5b3fcb0db83cd410652c8a10e41a0714fb36ac82a27c381f99ec3274ed69ca78e9b5b78ff90738e174177ae64ce5fff2f9d7c2e09e934b1acb76bf13506c9cdd300eb4bb0bf3fb389de2c80ca53056b81c06198b5f1e1506bf6909b27f4a64fd5acb283fbfddd63096c803a537d928857c0ad69392b1aa154d07dd979d2c253b540f9daf91c8870e4bf38ce59e7ba45af3ad71090c58a97f1f4fd3df387b6fb4ed9ff5e7d599e063edd9387124bb338de901c32ac7380a0a1da312a15e4c3c1faa2ddc9f1659f425adf275a7c9403cdbb24587e066dfd8a51524a68873fc4a744d3d1f9ef3b6fbd0324d9b5cdd387f419a5d7d6a3906ac86d888d62f1a17ec7cc4542ed77204517e465da7e7e7576c749d811c4d48b591a3eed978dff11f5f2773c497b4cd44eed51a0ee4d279cf77550954e621fc47ea00a19df5a035ddf396ce4b385e413138fb6aef33bf02356f080afef4ba6f225f2b6b8b3c7d1a7d95a65152d7ef03dfd8a64c579898b8151f0ea150f1bddce3dd0523725952285a58d9834abf955f35dd55876b56d51dc2f10285b24d0e226be55aa51bd3ae83eea9d80aaec356a053410f3510330dadcc01d0138362edf04d049052a0d91a2cfc06a5d9c81b14f202406b35b372c973df2521a66fc19a8560fe80cd2af9ddcd2f4111c694ac717e5c8f23a2a93f6f88be49f81361d8d920be414b413a3e5b178c7a95272d6b6cacb3a94867f1e1ff18993a1932238c57667245e5139606ef41a1f16431bcd66911e9164edc53a0403b8e5d13ec124dc678ad085f67aed61131c069331c32d663d15890f8901e73416642b7b1754a825882964c19d0e622e30a48ffe4a7fafdab4605900e819b3a031abda92542789abfda6951421e66a498bc3eca0cc9a313e93a7f2458557a4c0ac16d6e63a82ece7aaab8d89f77696eeee43a2982c1f291087e5b2b62845d3eb8adea8b34cb3930087e27e4038f71e1f04efa61afd87aebc7a365dd7ef09258ae1ee7bce670fd6732360810705f0b85838cf8ab67c6910fb01a79009980d9179a5f55d145731cb2f4f1e96a4c9757d6a7b753529cdfeec3b49b01edb965969fbce097abdada0b8259510e36b48f7fc3022de9efc8149342d8fde50458a04286554a53c60b4b70a5fc81e429aebfaf04bc3fa2cf93e40e5bcbc9f1cbf03ec2558400225a211318c700adc53bf4a7326e64ac4d1e2e2b2a1ef2efb33bab90265887663b8e913b241695003f379dce9a8db77479c3745128d3375f30388f975da62a96612cf952eaaaa0ea655452e1e02b741e6a116fd3302e45c84beb3361a8e5a3b37369ad005151c33f79d8b443706b2ab0decbd73adcf5969d03eb11043b39568783dd7fc644c2a3f99b076fb8412d83f1c5798251c535186416ef9ef6c643bc05980b8bfbe7905a8bf11b25ce9ff2c043fb8d4a1e3b91c611d38b79e596c58026166dbbaf03440bf298eafd661b889ce50c626672e9c4d56c00287e03eaab611fead48be3278fdd7bcf787fa06a261647c07103d36ed9acb15d5678d9b3100eed84115d5000f6f026cf6e42a86a3fa61ec672fa9f5b7d018127ed70d238ed03c0ab3f4d112f7c08505548d679d491147b8e5a5820d4fc1afc0a03db611ccc5220a2e968cae3c59b82bb1c154c7f0ae86c5f22ad9cca39c8371f231d379a616c0412f6190872c2245bc5b208f21790015b2a877a3f794c42e01aa9ca08437a1416432477780cb860365d100bc352cba82aabaa2d05462513e044809135f1b6af8665a39a1e0dcff70dd9b94561fe3ec7ce1d2097f9c9dc52cc57136c5ad7fc542acc7b7785c5eb9c9563f47cde02d8d7fd53eb2576c5f8ee9d17bee2ec12263b98175e35b9e20a3f4c09963b260a1b2bcabd44173d7580655a640345d69b44e4bcd7743440f5c008108e4918dca3dfe3ce29e260034a972353fc4dfc53034cdb4a0bc10fa07a3dec9611397d03526c2844370465d3b9c28443befec52a88442bb4434d02b70834c748cde1e0aadd4850e0a413362c832b8d466a6367158c99bc7c35a7079c5a97cd3c5bdf09f9be7edab5bc723ca0f748b01616ad2eb4a375488a8703d4175c4a21ce67a1a05bb71b9e03b4379345267df1862e712b2cef0431274837b9f18adf61c41e4f50f56164f5453727bd00493767813aa51d78bafb468db5a00dde01862b50955de2c7f221953ffd1663068bdbcc42af5034430eb0d000daa6fb8a9ac7dd7a70e677be1156b317d88c34d737491db2ee441bc0e7f23b65cf58e1204fccb2c3b2b747b3e7ebf74c6b10c8635ecf10602bc71668ffcd0e15595fc8039451fae6c98da0125510201224a91c38a03ca31da3541f15881fdcbd2eca6dd99b33ae727ce641ced3bb8db4f99b572e37836be31e5fff63dfd4b08a2b9c4807905089c8f035b1e687c52fa405dafc2538bd94cc43276c48f470b1f25c3867a1c7082fa503b05fe06b3196fb009f3b1772d7c7f6ec2b0f3511dc8ad355a923c997ce1bf1b9abb924aff258bdac0a87146f239a4f90382460454f5848801b15430528df3b8da16a4a881975d1003fc6f703f6b5ed706c66b1b1458df1990f5a943baa400a43a4b25b80f5152953611754dfaf23bd0d1e647ca338c1fb1bcffc6357f71b80e70b53ffa57c4b47df2252cbef7de96ac8db846585434b80b36d0c2a492778c4ef731377684e4ab6fc6affb8462e7df3ee45ccdd314ffb0950a98b53d3db331ba263347f8264605d906613f298a16244ecb7699d42fccc71622a4acb31bdfa555d07b30e3b1f337210cd3e44e06f4371d92be607018193db76c20cc9b5468498d694af6a6c455cc79fecacd4ac108ef5fe75f8973e80a70403e2cb656e4b4c61b3afd23a1abe6b0b91124a189fd1b05043a3875b7950a73a6dd56d483dae947cac081008a95493f371d6a1bbdff66d34d3da5e537c7b3ea83cb220cdb890709fb731abe85033370f297cfdc4c89d4658ca0148b84e1b2dddbdd1b6f294de91505befa742d40a006969db71c05405c8f34f796d75144afe9336ae98cfd6f3aa4bb508e5b6142fcdbc233c2b460392a83a74320d87af6c2a27e1cf93d8571c37b45489c68b4f43520ae816a1fcb2fb7478c97d5ee4be4e24f9012b49ed5821e907f3e814d2d0845ba267ecbc16c95b72503ef559ac6cc623c1a07b00998d01ab80ceaed1c1c69fd6e8935250f65a17721bdcbedba82f8b20a6a4ec61a1beae842a10a0dfa9f8b31c9c36c3dbdd9fa3ff66090aa1f55d442e254d9c02d6b79df51d9f8c29f3c34dc9ad1eb74dc2ba5d5e1d4d1822b04bcf5ba71be3ec802dbddb98548dd733f35837b07f476c03e05d24736b043a1001c691c6234c63ee8acf39e294b5bb0d1160293824a64e5329018122e8951703b075391ba26ac8a06a773798b82da9330b765a26ba297a22673a63f164c660a8976d6f71a5403bc62bcc670b31837550b0dbffa5ae74401fc032a9706af9c6c0cb737f8452e03c28146b0e0d79cce0c44320ac2bb0d3df6a13bec7aac4d6d1d4b4209872fb66f7f5054241d508914340e9a3a4134ef2e28f47177f652e578df452913aae5fe188a57308b0322ad168efa1c52cfc78f7d63cf6afd6177ec8700309de7344de55cb9dabe25b4e9cb68660be90b10ef3c29ea83dc260a7cfa208ff3f46a23b3bccbf89d7d2c5250439e6993643fe7b26ef640e27297b1efbc25b765fb547c3f9d06c8783cc40a9018868560c79c72737d5adf45276c1f19d256a6eab425e05bb0cdc1970d707ff8e9822dfa92ba3ece18ee727bd093c96af96a72750edcaa8d5ebfcc18f360a637b352cce90d561e1a182139376c68e69db7e600761a6e2125bf9d20eb138b71cfd9a9409def9a8df0ef5672a6375468d6e26550c9ea68aba2437cda8358162b812e8c464e85fd9ee82ea166757432e50f2a28222e2ee483bda0cbac9cf77ad2018b0897a3da8fa3b66fff072e4313954e8c630ee27f72b67011c315c9cee74847edbdb1dfe7b569e199179a813bde1c543b7ee33cb53fa9d75955aaa45eeaa57243883b6be6d83f0ddd74ba9dc9a3b3fb59d423c15bc761f1ee43e8c76cb624a35c6e498f092bb963106ef5ee5e765797fe57f9883e4a19a0fc985d661ad03f4b24c870d1c56e19bb4177218a6b43bff0045a211a2ac42d8d550048a3787153268fa4021a38ee053d646d307f6094c26bdc04338fcd436951e6fa625db0bde033277b79b3bcc0d5a7ce50541d663b50b1b5dedaa6eff19a7e378c608b9dd8e9c80d11a3e97a378597f7eae50a9d147719dbcebdd3e90ad8621f5fe2842002c7edae140a81ca98777784b2847413712cd590a9818b60ef7aef920a4fc49f7b6cf8bee29d37119daa5d09ae5fee2010755751ce2cc5273270cfb51300f35cd9de8b1d321e5f9474887948cade072c3f62e9e1e1b52e3a6168a1f749b1ef20489255459de19d3fcec6c23ab3c4183094c2796a1425e6808ee8012a898666e0d590840495436f866cdf26e3b7b71ae944178ca05ae84561337a79c21ea2b78716dc8f7837a5d37a29d39e674a3a2dbff43e82172fcf5e1d49ea56dab499c6d6c0ba48ecb62803b3462d737e7ce2f87d4e519ff7debeb9c13aa47cd117a0da0d5508dfdc998254cabb227d484cd9d3afdc900ad5ae7e301924602180b8660150d074e5db584ede3385f650b5a9e8697b26bbe36ead81848db3d6e34f404d54c1026726fb32c6efcdcf1b913c7560658124a9acc5a964be28343de2c4419ab49dbc12ce88103761f52bc8b6fe7eb3cbe77684c8cfb5acdbf9b6f4239c32843cb6c744652485198a684ab810bfd32b486a858dcd0698deab19fe2050b3681b68acdaac88dee42b40c8608912ef931a80107e31998c31069e30cecf3ea4ffb9ef0e287716d9c662b03d9dedee874d61fb349e9264d9a6f1a63bd71caf35288b1438c454e55cf561e7f44927250fbcbe0e432b990d073ae2704ec3d283692935d5fdf63df975a96da7710fbc0e134f0c97bf2beceb73c77dc4645ca2e7c31dd8461b397bc2f9da3c73af33ad57dd662e9dc3648cc41d0f4e39d5b8f35f86faf384798df9e31d913aac5ebb7aa702c2f92ffb0e26de9bc8e2af1181e4ce9239dfebf4b93c60812f77547c3b37d85300bae6a98a9fc58d881feea98eb67ae86a7263a1b63624a1d9a9c7edb1a5b6cba1001f453cf00016459d8947e89e42652ce303d8f830e18237f9e296210970b33fed55c77201dfafb60870c5bfe76681e7c1066e7b7abdb431482af01bc87151f9ef8b561c48c356746ceafcc770288913132e29c1a94791c0db52217157dc3aa09669dc2b8dd1af1d752e3b9456f5e44444fc9deb390d29658a4dbd7b845b1866ad83ac76c505b9a2dc2254575468d734d6dedf1d7d84a831065e8beb3e193498b3d7e373e536fdd0d042d2eb43dbd07358e69d0887ba8452c77afdf5528b5cbcaeaad3649b36f92e594fa61f5fdd6dce4c52b9e2be614ed5692a5be50c937ac70a4ff71146d42810b9b770266ef60bf961b52abbcc1000acffdfb20cf46745447e2fff8136cc9e4019095780387e459b1bb4b34acbedc742562fab81c0497aa942dc98376349859f73925d9c7b47a51171459ed0a3501fa2a2641307c98c82d8707cbfd3321c97eba356e13f883871b6dfacbfb4d62c1b562e5a3a28842d6d47e4cae48411bf78bc9313924c9395e1e64b1c3ca8c9c33437ff993ca17c3697a67c795a9bbf7c839464b00f1896bccfbab920c0801e2ab49a81e48c70347bcdc0cc0e147ec1ba9f05aef22a5a14c5d5b373014c09dfaacbfd978e3ec81cc751ca8e88c273a48b3ab9623aef5367deae242a5390bf73f7a45986141c355c6af9af7ece446df686353d479ae652788f164d67eab39ab67286fc0e857df8054311a1dad89282b4bff6022b045e46440d1483ea9213942c8a72a35337df1e4ab7fb58a7ea7d7f7e31288281d94d98481c6bee895f2bb867c4a3adec828a8604d39afdadd7dd07c78425853f3f7c769fb7e5e75a5447793a6ebcd90c00a26af1afe88274900da0eb715ad77e972e847b55f4368beebf6bfb4c548dd24b74732e7b6c1604f5c313c47ae0f3f4992583c740445ef99e15dde2d76013a73e176eb5e2f145feb4aa4fa1fb7934d68c19ba89146a01c0b5182573c46452fcd270e8ad82833f2b27fa1b127df8781393b25c352c367da05608a90da4461afa1550ecd9522430fc3b1187f47ed4a8c572f9b100e327fe611579dae7c73c593cd03f24fb15e6bd78196db34a72fa751850f3f77f8dfc3bcc3b34a75a09669d9c260b6f06d7981f24fec8d3db55f725fdf4dd22bbc2a4218ee6dd5daf3bdf2d9492074eddd85866e8dbd75992b394c484db2fdad59a892c4ce1df4afbcfd7e65cea63d65c8c1e7b63590f4aa7eb25ff2d8f60fc23a220e464d056aa228cba8a9448958c601b94ed4a1af0dde5e3fe25363d7dddfb2798afc64a9cf7aae8e9013e01e9987bde3058608f6fcf6cdfd50b1349863b21f3532ed3bce845198a8565da8489792cc714db5d8a0c53163c95df81ea31ea45b88f686fcb268bd19cab2fab7aff49ff20cc510ab7d576245d4a1cafacf6875ba7fb1aa478304a3fbcb81d0256a32ea22321678b67972034a9e0d226a2b4832af7c7b2ae75dbc918fd0d587d6ee6c214eb17fa33821ad2187cf6824d4469e149e6c5c3c62b9e5b960245b989503f43e050ab25ac9490bdf1b94f78fb801fd1140b209937d4f90ddd01facf3d135a8cff99241ac256226a31f6bce2ec3c29ee1ef86300c8b2cf4ea621abca5e9134621b6e073e844892f71aced11ae9842b9729274fa2faed7b7871453bcc3e632a5e6feaf3395f5cd1fa75d87817f2cecde5b3489aa57a08c7b78a6a675ab4ba7e48854bb550473b1bb632f467e20852d40d72cd4e288258fcc245fe98fffb18b624514166f49ac5c9bb1a247f31121b1c6388f9e869a170a001de49ac979ec589463d75adb6c3183b83a601839e4026a92546a837bc7394092289c01cca48d4a89aebd863983156d70f3038628bc1120b4b9b9227fed23573b6551359afde272a03122de31f22724a8491915ac63b9230e3391fd775c8b0ec885c77035bff47c175f746b32f18f3cdeeb1e44ef5fcdfe998348522ec526ec979d14af997fc08acaffb41ea6a6c0b775f5daed1b80dbe255b8d7c7fa49c0daccad1ef820f8780706192da6e1348ddbdef662fb4ea7362f249daa3dad4c6ac821d13d027bbae2ffc5b6ef7b9127ddb99fa8cdb30435da1a840ff3a8b0fe6e3d1b75d49094e1a3dd158802d783d1fa5d7f6283cb1753274ce23bd058040c2d455dfc306b550ca74d52432c6dc2505fff598fd1ab3a70619815408b68deecc223411802c1c7d394bf76d43081e7c8e805618a96b6528182201fa2a90c2c15b2b88de9f621f08c6ac792417a9b7318bcdec72f710cf55f9a91587a99dcfaa2230634b36d9712171dc6f9126fb662947c59a547b475f5946c2f510f1a12e848757a6d5d2dd4a822f0f5d46d0b9afd0e94f93b6039dd347ec214af8cc61a9363be36352c0b40b18e16a06cb550c073b7d4bfcb2c5085f90296f6d148bf589e1d8fc9d227b925e5b993ecfdceb43ce5b7a358a36b81be268018b4e590893b5b846bae9898cb83cc237ee613132538d18a0204f62ab7274d14ec6a3506bf91f608f07766363ad75eb8e81fc8ea216af2e53287c8183c82f40c35cb64600f3a199e707087bdc14f2e6b692aa81f7dcbbd38854663b798273ee85b6c0406db1677039519ded5ab9ddc438426d89cce4ac5dcf42466a48ac52b6c252886a46d4fa7f4c02b5369d31bc2821b23324477829e9cb8beebeda63d048200e53d5075777a853a67c12801840947e5099cd4867aa3fa640f5a22c568600692355f1e4ebe10dbca73d6d28c21134a996d703fad30b29d33ba2063c071a782ad1b9487863257fb53dd643740697c0a021bd1209f611873deb2a11083ce2e2b0cd3831f29dfa0b06dff9ffb31b4eed94bc7703dd135b3ed7caa8f211456e9d9e1e9e09d02cbbccca814b885c03c8379916fc810fa2cd7975d8b9107a58550d48786423abb034c46d567bf3006cb15fbd72935314dd8cf49de89b54fbb60821886cb35e1d55184ef548438479c5ed259a9ffb75a40da3bcd444aee55990c18235650b44d0eba0384054e23fede0a112d551d4532b0e907ad919a2837c24748387f28ebc47ba40f406431f9240ad01532e0254fb13225ea8d87384188ef95cdddb1a79281551eac72ef5ca65f8afc24526e98918347c0c53b0d615f6b1c4f57c7d9a9fe6729138380c5d9628deb253da149a9d9a95848f07cf78ea2c635908242a8f4125517008cccb798b2422861c52977b56ff4148efc67c031216f51700195b7734e0c0f3c155b12ac2c73a9da8a7aad725059ae61ec7e1800757242e3f20601ac71f64baa2e8835cebe4902cf65ec7a3e7fbf9e8c599b946f06ea9957e0141f7a24222da6c4260f6152d326834f245ba46473b1df90a60df06923ac7456dd44ac22a1b60ad81ae93080be048b2ee935474b06a73ee36598832e1e4c30e23b0fc9373106f107c031817c899b2a6f5d027a49f84b0909452462d27674d274c9a7cdd71aa18b9f1e30b46cec09d55f0915269506c651709b3ee5e299a1b9758961c7f0cd270fb728d216f78bf923668e6d710d52b4d20f01a2ba229192c160e01df1719288b664246bf7bd2d141b3db83c838514e23e5ceb269b5fb6b74055463c2f40a8551f1440c9cb41a2a26852475332f59cef59701c40de4b6e5f514716045db24194826af67933134b80014ef5a72f43deb286eb820c0c19e45db64c56a822593620b0120de334f6739abcfee432887e29c2b101fd3e9c31e1ee274b6b338c2884e6d4d317efae08d8785b3c4035397d9221691a11bfa3ef450227cb5f1ba0a4c609d85d3195587e3f37827c5ae54e990e92dea752b84e7335ea2e3f4d593d672599768d25446cb35441f81e065094cfa4755bb5816e5d51d2586180a83fb6eda9a1331fa00f3b38f99a0e969f7a131ff9ba9d520dcaf755c8887dd48ad9c944062b7bdec8cf37ebb1cb679c4f434297c29ef16cb74feb0fb00530e377ffbcfd9a0017a110b734dc6d104049c0be80be84f50b09e64fdb0ac75e47ef355dfe107f3c9390ad39dc60a3e0e9fa5425e6e58e51e68b132504dc7873e4d40997611f150112d29a76a929c6bac5a7eb0b7f4ebfa2669b55396338ea9074bfb763ec1ace13278093c3818f628c888d381766b754f4ad4803d47ec86947ef39338f15de7cd0683dd801bff7f0b425f01f9fd88efad71810943084e642105b0362950be4aaf","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"5616fc32ad96bc6054a97b08493500e0"};

            // you can edit these values to customize some of the behavior of StatiCrypt
            const templateConfig = {
                rememberExpirationKey: "staticrypt_expiration",
                rememberPassphraseKey: "staticrypt_passphrase",
                replaceHtmlCallback: null,
                clearLocalStorageCallback: null,
            };

            // init the staticrypt engine
            const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

            // try to automatically decrypt on load if there is a saved password
            window.onload = async function () {
                const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

                // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
                // replaced, no need to do anything
                if (!isSuccessful) {
                    // hide loading screen
                    document.getElementById("staticrypt_loading").classList.add("hidden");
                    document.getElementById("staticrypt_content").classList.remove("hidden");
                    document.getElementById("staticrypt-password").focus();

                    // show the remember me checkbox
                    if (isRememberEnabled) {
                        document.getElementById("staticrypt-remember-label").classList.remove("hidden");
                    }
                }
            };

            // handle password form submission
            document.getElementById("staticrypt-form").addEventListener("submit", async function (e) {
                e.preventDefault();

                const password = document.getElementById("staticrypt-password").value,
                    isRememberChecked = document.getElementById("staticrypt-remember").checked;

                const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

                if (!isSuccessful) {
                    alert(templateError);
                }
            });
        </script>
    </body>
</html>
