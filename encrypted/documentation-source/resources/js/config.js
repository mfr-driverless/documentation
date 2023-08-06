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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"ef3b2f3d7d2dfea98d7909439c37a5de542fd4de0ac51b9836745672a7a3e6acf6b107703772cf89879bbf80316a690e46b7064f7fda9c65bd4f519698d30bb5f9b10e3ff6b8c428fa19e4e3b23df39fac4bc302026150030782ad8b49cac5ce8206a13f72d42f1c2f245f57644207ae101e5eb7fbde27d6427e34e7005d5a67f7ef5658a1b7c766cd32ca8a4fbacfdfc25610d231b98c2636de84c4df4ddd2764e1ddabcd39ffa0248c65946d7c6f32b9e75452b4eb7fafa956e84fa4b5253a6045ec08ce3e088c12ca1c74853a295bf0d26d42cd3d6034923f08b3316ac1f6552ee3198242d0121c03ff059259570db3fc1e15572023763d3f08e10ec6c4a4d42e6731f5c6a270d4ea09ea3313380aca79e6789f071d7ae22aa5c757ebc4fc69a757b968741525fa805074571fc1804ce84f7b400e930404cb0f7a8478211a63a2294e8df6cded4a3a5242af48db7a0efa6960a97696cb08bbd2694f4a949231b087bdcb4d43e8b56282a8daf44b6274c6f475165649422bf6b0722002bf057c5eff7619a90d63723e8efcca95888dee56d303ffb82d03a683e7c695faed43ea860c71e5962db04fd160550be5e3b1c660bcc354c3eb832ce71961ff8ca87e4d3186c2033233a0f5d0b193e1064a04ea62f57f7732eab2e5505cc898ea56f657a7679bd90186db14c39a98a65d42f42d5d16bf294791436f74bf2244735435c97afcf17fa272bba8a19d732406590f0ff25b1af02ff0d37a8b9d6eb3c1371b7ea0786967d8222473c2aaaac759f1dad2e9583386436b655b61baf1adb7bff0d031f1d5edd82dcd236c4d7174592bcd62572aa940620ca7cba23bbc88b48fcbd9f08cae3650ab1f85ade16aae2a6125eb1c19ded77977b1078504cc2a774c3790143771308626a0c28147219a4f7c286f0ecfcaa52e67f7101ae7c05911b5372471cc507da326da5ca43ff32066faebbf5a5751fc798a4955b9c6b0d456e927dd85faa71590b9a5e96013703a612b10d59bae612a06ee2adf9438608e31f916ba773eff038df4d2e2c262a7f0d6dae2f08f46d1ef52ec19aaa56a4dc74033eda26164393463faa8c671e39e5af0c62ec54e20d77dd99a81aae1d37462a17e5a40e34ab4849d1714a82e4a94945d41f8873abae3f3fade139b4261785952640e767aaa61e5837dceb7fd3d9f0599a71c25fb96f55ad5e81ddd540e1336d5785ad82e10234fb1d1012c9fcf7ee83a8d76c286f53bb58b5cca748f30454e9044e54aed71df262780ba1ef93b50b84e692499e235281e479d1f2857e48386c670640f7d95557a39e0a6e958c2b5b6dc8cbe70c9a3f559964827656ac83e6d947a0dc9962b32435b3bedede47528f5ddd1acaf00213b035c58535ca5cddb552c98be3833e9877db47ce08c41da6cdf8c56bfb8222164d0d2c82c338913adbb72b5a622943ce225fb0f69dfb00087bcc2d7a041bd881011da6f6bac77684ae809017610b20a6b330336c917d19953e052759f26c31c5dd6253d42cec7d3e3d9d18ce621b3b6c4b2abcadc88114399787c7e57781d77622ac5133b0b323d52c52aeab9ad162f80fb40e2a7bc149f8e7c18a448daf76495f0e641069de333358fc7d1680b7012215605f859497e1bddff4e16d47992782cafeff96ef3f89e74bbd32e3d237bf02ac52ad661366681368206bb7e6ec7c615c7a9f2702c5165981c8efd9c430acc74446f19c6d87fa8e739a1550bccc8347a6a6cb86f7a8c398ebe949a89346448ba6cfa096e452ce25707aef5e866cc2dc4d91c6f0242bf42c470f567a39cf1f143283beb1170d0f6220032a2d1755692c8315767124ec7ae6eddd15c6b66b1d1b4ea9cc37c47928af7919b910476beaff3a842cddc805d05557b4a1e5eb261af7fbd8b44eafc9fc57645ae74fd0d1241187f506a5c52bc330ea6bcc9670a6984c139adba732b5dad61be9f5091faee0c58523a812ebbde1ae263e694c13283d02d898fe5fbc0f08d746f1ee8cad97c62ff7e749636721d77c31c88c9b0db35ed9555c43f63214b7e7f3484c826c7634ce2a5cc4d083c157aed28bd2a1fd41fb7cfb65f3c8677b9cf4ac15f7d62d515b3e415984db3cfd6e00eb9532966209343576d752dba1e1b85adbd7030591fa54b064d67ae8954a7fefefad7734386bf09df7368234b045f893bb10fd18d89525c009b68b4c2f07ff862e373638a1b4ac45ce0e6d5a80aa8abb8a34c760d8d4d41704db56242fc48016af7b0e07b153b1fea86fed5c9d73ad0e872bceb3dcd0663402ea82a90e1d6ff295acd0efd21986dd94e2fe88f0f0a258a501551f48d143718e799b3c923433b994de4de95323d7cd73299f5cabb98c31c012fc1bd8cd392bb4b8cde14188c1c461cebecc24af2008a8931f313d67714737178cf1743420fef408c488b7268af961c1ae86f029d5c28f17d18552ac945c6802e67f623eb7428ef79eb5e3850d982eb7285b524cce10fa34b6f7e6aa3a45c375620921631a1ec6f327d876138b055bf8269a95ca7cb48a7de5661cd0ce8c421e2d041cdb6a704b404a298601573b1f0d4ea2d8ceaa3212e5e769a55a31b69c64bafd39051c4417e5727700d5c7580f9f41d87b076dec1b3ec106592463ca8867976ae3f79f7f25c0cc7ae33cd17d2d3d9bfc2a2ae9f3251a0fb8eadb773188c4abce50db661766d76f43fe3d35de2a5be254877d6a9386da1c10eff34ca63601c8f85b6b8951ce15fb6fc73020d806baa31545e7e181e9bed956aef65a0d2f898ad0c041b3a2d129f402273d02dded29f8bac77a1e5db5cafc2f6b7bc33e5c5072bc282eec1860912d2589554067cc43928b430c5f665f581e932cb8984dd7627571073f40e7ae97215f3da8bb460fb7db63f9489fc87dc2ddb826ae5d48c30ac4ef654c487b9ec1102c129aa4e09c9825862eb5d27bc36f117a1c04094c5a411a5ece84645244f763831ce82242f5c64c0a7bb6c65d10a303661d2ad82fcb56532673cb79d49667b060b6d17e3d5a04f912c7e3915c5433dac434af77f5dc4d8674085b4ccffc354430c520a17b8f15db8053f76574b5dd0a48d1ae39ea3ea920a4f2bcb3b4d7b78c1c6b19d741f5e2d874c77d9a3331f5aa3de446739ecd221636b7a815205e2fb10fe647f57bba0cedef9b659d34c40c275f362173cfc6d43da3a77682db6a213ec0ab3343bbd108caa5ffda60c3f373b57bf9a6c39fffb472b2faa28a5a75723b7ce33f286012fecda937d268995c466d5b62ee0b54506f91a4d7d177fcec5660cb664cf7a7452604abc93893ef2b673d8c07dba0fab37dcba694ea51a3bff53cb6a904f634abf9cf7c50d3072e39f410765d800fa06b26b7873bab0a249b49d5513f2e497952ceb1a8bc1b3e6d5413df6f17e9d53f49014b32b68d2d4dd35b6c4062850d7580b51ef7d886c2ef8ff0c7eeac2ed28ffe7a667d36788f5b22fb14e0232374e2331b97568cfe1c9aa3a13386e4fefe30a690e045a4982f97b0e9168bd6eec060fac1f7867d56e83ba8c7df459b41c3921eeb36091eb4cf10b1a601810671ac69186ffdcc5068a0cc856612ce442bd0dd9dec08048dbb0520c800154b7dfbff68c9424dbc7f2d5e57c7803095fbdfea6297784f6ed4aa1827e966db24b1e6458bf408d41f1776df84c82fb9ebd11b41756923ba2034a4b57eccaf654bae049ea58ce6111421350b35480ab954335f6bdbb46f0c23ae63c55c32cf6d2f86042838481c8f9163414703a5f9779e4f24ad6e597e26ed23e7f33319f909491569905416fbfec692d45c30ce9fa9783d18ebdd948c4303eb990cc77e054260c48cebf2a455de12943206fb9b858d6f79125177f0b6730c194420144144bae88b2bd7a51ae2eb9d639c8267dab30a5e7d6b540d3bd4bd7e56b3685293112e704c871019593f5a6c17688468e2a6b61aadee64bfb58a3374244a2533f05d7b57bf514de7b59e28b35e00563bd70c52d1e407b77f05c2567a379670d12e1026b8f0f9dd207f89e074cf4f1df4a1870cb3d69f8ab8f80ce7d0d7f7d0fbd9370640919bac8ddcd661d1cd34d425fedd31fe1750c9cc4cbfec7a7fb2c786174c5ced70e7e5cc26536bb096f156dbef859d12b792ab2b7f0e3579920e65929f57395659dcc2ba2bd4663bbdea3d9abc3c2960a8a3655dcb246889b6839acb36b9471f8e2c78c7c9f31a7e9d9f9a2a99b0280d0bb00dd0410ce104dfca7a1d87807220aa509f37d53ccffb64fef6bbb8e71c0e6991aaf5f7d8f2d4c6e869f752b8860714620a30005b9c396600318dce1f1ca0ccde3c2f22087ffcae923d7295b89ad8eab323208d21b4933dc2e3d73adecba672abbcc1424ac9882e15ae2703e5cff938ce768b223e0fe91ba1d1356889f46614fbb35b8bc8e9ccf6316f0722bb3c9bd153901c8f728ac7a90bdd5cd7e8ef1b19f60e2d826992aa59bc188cfac151629a2192c1ce946e3b5a2ffbacc5e47334e41c2ae4590dff0dd1e9154382f9b69ccd6ea9d9574259cd198d9a7a9fd1cd609f5e51905ae1ccd567ac766b0cf8fa1441763d5dd0c0f7f8fc6de848e443b1e653ed083b46257ee873461fdeee12454ae3ea37c7bf1d426a6a21af54cd22cdc60e3f824b29df1c7324c3c1a5fe13c45bd308449989d5c0ab3197206af772111672475b7d299989a50ff99651b4f4b8b9c5db70efd43df348ddce831951bedec963ed61df24058dac4895462b745f3fb02e3ac18c8b19f9b4c9feb0b404ffe63aa850affa19f26f13c3752c80c0e3d66ef0c96002bb7da95088b9e726ce04ec5eb4c7fc1377f2ade17b5c8568ea83fcc0c7dbfd239e44c0047759939223196c714afd2e23c51f5beb4da50c7517b3591a356426999623664144ae2758dccf5df4a137adaa58513c2b3a016c14dfc4f79b949f7bee133381c286feb8922f1700d8488aa968859e395b27cd31cb59b9dd930abc03c5d8bf34d8232d2dde99f4d54a5b795aba0d883cebfc9ffc2eda9b87b76c1ced5d02938dd6e94450a32b83987dcbfb7e2ffcbb49476aa5b95c2fab279111563594d3df617a69e2a20f5c1e6130589fd987decc41ad9ddaf373e16a63398db736136b0cab52e0921ce8798113c49a6e48ad8938c17da081b6ab31cfc7781379b28d0c48966fe59d230e98cf157dea9a134b853d75d99c720e20187267e99b5957d3a19e51fc09a82d3741cb62718444ffe874f9e2a66be22cd2dce9c46d4d585e764083b169efd7c31c94c3d3ba8cddf31fb9c388994f7f3ff02795923f909e788bc56a740114b050850fbc36d48121532afe188b8521de58a5bcdebbe10c92db273cde3d35fec0ded3c100676920a521c7aa4ea7c33194b324bfc3e7319ba855b3f365d36471ef954e57f3741f3d80dfeff249097be8000b2cd4f73301d67d069eab781e00f18922adf7e16ea51bad856cda781a88c135398d27d9ea5468c627d1a76b01a89ebcbff4d00de7be73b3fd8130eff43db2413f9595e5cc5fb77532baeba9fe07bfb2fd48721d492422c60e21715754dee801e9af6ef01a8f409a6e53911c51ffa5514a8444d4d1afcd37871f26d4568d66cdab774638d6b579f3314f82203e3924541b09d547a583f488c4bbc32f375ffbf94f3779391147f05bf66c7ba6e4122a66e2154adec8c0345ea839e8bdf2136df1f1d03d0b8c85bcfb8849a00f360588c699fd3c921699ddeb2a9b4def0f6e03d83ff596f1dc42ed7da6ffd733b52cc14764808f378b818d5ffbdd933a7e4c0ed6b72b71260957265306b2c97204aa13be451f2e7956ff77caa08ac31ceb86456b7f6f671cfb91933b86962e97928e9d17fcf442042f8ad60c484192ebe825ef27906ce91769177646d43a9bb068f76a1e186ebf2ca6fa6fe2c17ab2334d2ea3d89ef1d7026f1b43f546822ffec13b4000a08a414974e8bb04bce4f78889cd66d028741a98989e370df43110220e133b143f61013a942029a7b8db7c0834b19617e6a1ec3adf4a057e223209f6766e1be5abaa58e9e14b038e384cd62388287844d659b2431d9a6362e8e979a037a2983890ad7846c7d9a179cf0c645e6c0b01a1aa46f01124d86fc2b6ec665eb1b04d5a0418b95fb7702d5006b15035566bc53b5bfc19fb3d749f561c7c7b9df8a33bc6c8b6fc17b99cb2b4f5d89b3cb7ad8dd1302995a0e1e4675988504e3a7d22b69a3b57127238da9973138e450905d0c740d03f02197b1ff43d92a90f09a263aff5e4141b0f8e571af8235e756cfe2bb116b0de44e519c65665c1471bf58d882babb213d08eb30fc8f9c2a103455da2ee8a61e920a64f4c493f68982530837bb969f73bd3b40e42d1696185e2a80e98656a212aa6b73a474f7087e4badff5100ff877dd772c0af73d958b7e6ea1fa40363726a99d6fde64ea4de6b41e4a90416c802df53350940b8e5c84944ee1ecf9d857b0e5f59d644658f7224d8cf5f092cbbabe6fa53530b3fa4a90e96b28e9c9e82a15e93eef368d4cd18c0c15f36dee1a4469142da051b0b3dd048fbfad5e9d57afbb96e73bfa7d9b03ab5c5b1729fa93a5825c0bfde6f4926fffbf3e47d6ad5dcea6fc95ba47c18ecf1f73f2bb83ed542cb24c66c46dc75f2f70b4924a491485e06a116e9ee700c2410de5e7f96dde2562cb463886bb70a5748dde2e5596a4279e3b1d56cff3ac2f5f75bafeacca64e378d4473290dfe2d016cab2f48dea9863c169fd7e76cb8c3f84f145dd8cbd4f32d57eba70a97d2f80ddd56cb28500020633aa6e6d3b3051acdcc158daf124d7931d081bcdd8f7d0cc4aec419c199567ea8b572861333ea20e27f08f5f947eeae313c73adf08f201e6ba0038a46938858ff43d5f68ae7acff17aedbfaf8afcbad209b24336f817363031c59921f2f0f0e51756946ff5d0b75d2e9cae2200f8ea3dc3a6797e77281b80a4a1d7338dbe253e64b0f81541cbc360a724795095c7bc98825c766237483f62a149b14b72b403c37f34d5cedcfe7d4fee1949158d90a4255da72cadb52e1545130c934e5801f6f9ad2520644cff189f1743da57de4deca771b73fc91669e3710b8f19ba8680328793a5bd332e1c83c9559ec26c1ca7abd1ce94ab437f7a7ec94478598948ea0f8b1a4a26e43d4756c7fe771c140dc59c7f1eb3ed2c0a79522265c5891f8ea1ff393b1056ab07247bb50068f0787ca9434cecbd7b0402d0b52c2f82edfb083d59785fb3232c87b501ef99761484ddc21c52dd309632fa603d5b5aae91a9374fb3a3df9cbb7db65f431c9194bc66990536d474e56221756585b6770ce935022e4d3914b88b155b27383a934d3bb648f2f39eb709731675688ba79945acaee8e19c313925cb6047848ccd223d205bc231d384cabd3db2b5feb4efc401b82500effcc7fe78468d68210913f1917e7c604326763d2d1d4ba09f9a7ed8e09213490a341d480f28955af1986791fb85a1917c32c001e8e8547b264f935184cf71c3b68d41ddf6f2628aa3c4c71581ec88f8feedf586d70f833802af09e01506e42d4959315fcc9f79a6196995daa925d9dd10dcbbf71e7244027224d231f88858c3fdd2b81c5efce8c53ce8170ab03be6d7a35c9dca255d127dbcf00b13b72561acef07c799e41181d9c1669b8d643548d3a49d8b60a0d88d6240a82d9399ddbccfc6e9749cdee8dc095144cb0a294de415896d874dae94d6ebc8c439435f76278306fe3c878fce6af17d3810bd1caf6876be5b8340cf22f5aeaf5f4376dd97bc33e125ece28e13a61d355e5aeeff20f3acffdc3e5fa9188831c872209a98a4d94989c0cbc643902992707500c4e4b07623b44d672115e0a55b741330ef7ba5a41fd1e8fff6ebdf6f5d489bc510ac49867fd79bba618cebbc0afae3c24394071bcd6a680f7111ecb93c698a16d54955b1953355e831a7af6d9d2cff730bf9cfc7271d113cd26fe8fdfa12feaecb8c7a76d4ae518fbe2d2e5c6f67f9ef646903fef7d1f85e2cbb8397a7ecbb4db55f7755a665e9bcb9f2c214d2400e13ba205b7c743c406db782d3ecd4c02c5dc753bd9badcc5d273aee9a7f42b13a4aba298c77de23bf3121f9108228248add50e7b2d33c02c86cbd028fde354f4d3bc9be9f6b9b682dba79d62320019f7682b5c10685e9a8de589261d0fc3c70ea690b62fee4d684f7904e920cca8bee8c31575c652ac52435aac287f0c3bb42caef41b506f156a533cc9fcc2c6faf3eef27c55e063e3dd6fbc1e0f9edbf2f8bef880085dd62401561caa6253122f1a44fdcfb96e8610e4beb8378a479be8946584908eb9c0e79dd9fb496a25cfb7b681927b74033df4d3f9432aeeaf0dc260a13cd22e3ce0f345eaa40aa7478e41d28d7b21c4ea3e0e91a28ac8abb6998fa713c7f8dc3ed4cf490b9974a52dfebb2f5739aff6a652872ff616ce7dbb5126c55ece780f661fa49246e56cf389a389b4f0c2f1d2df3aaafeb837f2f54e83c6b1c94efca4b4bfc811cceaf039f96c8f24aca00bf98b29a371a62746f9a82dfc7dc1d3ec334655e82afabcb95188284d55e578269c5620143c37013b795085a223bc4e682c04531389002763d8060203d7958217baaf80feb08e8b31582864863fb8585218bca75a855b79af1cc45948a926a593a84dac9fca7ac1f2e7954a2e5d2a76d7b87e71d18b09fc5661ba3a86e37dfcdd4bc3bb6d585bc8436ba5dc2e28c6a5165291e7b9183488609d8855bc553a500f3885e2c5ba59bbdb38cf809dd1d91a33b4356efcb1b8c49eedc5c6f6c32e16dac027399bf24fbd3d9f105c4fa69a4b63d5cc722bad7fcdc1e6a044d06257d04f1d73a623f26d45fb4fbd2c5a5056046ac3efb950e4112bdf81d08b470c2aeef1c1da21baadfc49f0a1df327260d56178f792a446a0e2de60363cc2c074053d153604542c0fa946c1710c1744d071c632c7913c99585f60c25c96e821447afc13f6a362d4e501ea148ece629aa272d998bca521e960b35cb00b334d1b88c0f3f4e0f14b99adb180e750a1170e19d318f887195cb51b26d4d82ad29c99ea0df355afd41336e2bba878cfa368dce8ac0417d963897259fa597c1b965d324837b58735d0e2a0e342ca3b3ef983638d0a7ed1df4329837a26c8ae0fc2f107a80410ab2e1f28674aeb7f842f8f6cee6cd1fa4afbf637982f5c757f22bec66fcb3c3252599351a6bbbfb456df67a77fabdd70932dc5072f4d271d7558bc889e6c3df4a800c42311f8a2974168dc20ac4516e0a2b10d7a9e1a57d55bae8cc5efe3a6903be0e7a1960739e4b289663d72bdd38f986b8add82646e97221035858cd75b46bec9575a6d08af68fd0f53a94c25984a49a3dcc29d8b483e88597809636265894b88c14b4481d35816db5f50f5f100523adbce73be57d982089df390e8176fed709ea4365e8a108d77fd83aa84150734fbd82a3fb5ca2dbd9a795e321ca876926ac06fb47b259baadbfb5c9d626a9d4c7889c9399368fa82bf17870fcffc29befc492b0bdbc9da0c79203cecfc335d54c8abdbda679711316f6f514561b7bf0222f3b5005770e2937f1c190f36b2bb66e698bec120e03373e8465b03ae89e167df64bf3b6ec03adabf121da9f5cac11b16cc46b571609c7746718064e95d428866e8ccdc961608c2c9a160a6bd3e0c6d31acba65e29cc072cba5374dd08076b5df6ed20d4d43b6981818597e4041ab5dc749e57d2d87da3e0168472861ddba6bfea9d76f74dfa1463bb913342f1219540b1c2b21796d4a6e7b2c89ff280b71e0959e336d8c06ce63526c259f131e894392cdcfa86ef68364d3bedbdb2c8a97a00de3fb420d941b639d508fd1a29b7487fa7fce742a45ef62177e3f04e89b2bf35cfb8b279c44f419bbab0065e74c9bc70a3ac9614445681af7b3616c37cb2ac8b69586e2ff022f4ef49b1f6e752c0b65e3cbe1f8cda512054bc3b14491b124608c149d2fa0bbf58eb5e683349426289346777040d69c7f57920401e105f80f288f2ec1f57c43b43f9c076bbbcb0ed24535dfc4e45af3b3b4f0e49ff5f7387ae6b1d4b79c7cff4dad1ee231b4fbb3627430e86e28f79a28c53c9511c5ee4a248e7bdd80a878c7e4a6fa9f19dbf7e12a353e8ac4a4ced8eabaea8f4dc26063db01ef71916509dc3ad73ad781999798c378408ba70ebdac9c07360b06bb7f40aa0e9872796c546fce971fb42a2fa1d8a0204e361b58ec52ecd84638874824202b66a349380fedc838cb19a5b687f7623f02866595bd067510b8d63a0440fd1ad23d1287a112f16df427666a50d65e2e194791612fa297b10a6c285cda9d20647565beb651decfddbc6f","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"5616fc32ad96bc6054a97b08493500e0"};

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
