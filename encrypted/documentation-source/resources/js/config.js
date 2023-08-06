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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"d52dd1cca12b02a115bcdedf948eec836a4686ed6f8a694c79b3990f47383cc14b6dd8521506d14a181a4d8dad578d2b61780409a6b6a8c6bd53888afe92e65a85ec1e578169e23eee39bf4ed543d8080c3c6d1b45082dd0947e74038013fea46e811f702661dbda2e53d8baf618aae572a71cd725febe2dead99f5f1eecae66c5590037de793670b308897f06dfe6ac84d67d9d2fa2959c31ee3b3efbdfd7ef5db38d94fc7d142d98ceb08488ed1886e2f9c24c5592fddbc4e1fe4016373d68d43f903d0768a87c83a906a4655302bafd383b96860f4a25d5990193bae73590a4073563e931276f9c2834b4bc49b341d1f5d2c052dad54130ff2dd4bb4a68834c7a489b5c471123c2ba9c94074375d09b600e35620c3634fc57371c2b27bcdf186d653a0298fdd06c4191766bf0fee079246370d23d08ff467d70bfe07549a4c6ff2fad206fecf042a8bef8f5afcf48fe61350fb940c361b4b5521e2e4070cf273669dd2559cd7bf424d56cfbf25e4167918bfb6949ed5cfb384149cd5028c16ffcbcbba70bc2bc13812e5f10c9d6cd48a99e759a32e04b9067924808ec3362439fcfcbbb09d3e9565218b6c56d8bf62f808517935e59eb706b8f6d66ce133ec099360610aa7e9206f46ff0ccf889f09d0d39825f292237024f851436c98ce1def9dfd34c254578f807f1c54db1683dc45c7fc4cb255729115c7db99f0f10fa4b3a9c01bc8c622f03053d960458e2d24bf57dac79a27b580c4b66212364c7aacf2762b732ace1339756a4027eea1fb8eb1dd60bae967182d68dceee5b37ac124112e6c84cfdc36a36eb07dfc0df75bf93cec343d96209b82098f026500ce135825c82683c377671f541d087568e9ac0a7e11153814b0eb730b6bf79e1486dd1e63c1f19870b36fc8e22a2f79840294fa8708ea76b86d0911e8da0ab81ddea6dc49ba57f3aa57f0bb9ce1461870d239456bdad791f81764fafef59b209382d69ce5b3ea2e971aff2fef6d89ba71b22762c6ccf155cf367616ddc5c3d18d676357fad3422369b25c82de87ba8c031694233b53b094f494b8715b2503d89d1a9444e1e486860695ea910417cb6cbb88ffa1c5a3f519b84000aa38b28108fd7beea12a37c66b0420db0a41388b82b5ef69c21560bcedcea226f68b2c2a3ac427be0be8e9ce9e9b6e7ef181f6ead7fced23802983064d2e732296e091f32cc77ad6ebfed9f976b864eeeb42dc2b0761d42c04e0f9cf3669cc72e717e964075be12f5f194c77b7b2b21fb7087b893425796a5b621b1c7f7bf93689a145b5ef86bd10da52feff8d0a85aba871f8dc8381dcfca8c71b2ad29c816b8397e682b9373fd9c5c8de43cda97c909c0d5c31c75502794ab519a9997cedc781dacf50e674b4e68287a26ac0faeeadff1750278cf14f5f910a5f8fc1fe74a1c59b89bb2e9eec2a75f25d0628f512ae7f45f18530390674c54f623ff9bc58d111142de0d153728321d8f40caa41f585500498deaa7bd229952396d4dc78afb4ad410d4dbbb55973fe371144e38fc35eb82bb517fc1f40d05a60d4cd6beba9ec30cc365acc8932f4c971494916f7134cbd594674449bba5dc9cf304980565f824df05e24260844817ebca1f4b9b578f4cd8c11591f1b40f133708a6e98d3d0c4510b9639627b214ed891d0d5a0faaaeac36748c4f0464dc7d8835405e622aada624206209906c75ccf520dfb8ceab53a5085f12d7e06c2196108c8f58fff8c9bb68fa7367138744837494ce2706bd26fe6e59082cfc424048d82dfa27350d18e584d18b20a29fff2078a59c835a573346c17fdc2e32ee6522c0974deacd36b79b166c6bf3df1a9f96edc8592e62e5f9244a39d1d5560a330a2c03aedd4470750f04ae2b216e3085839e8b68017972036d0c52af59cd6011053e021da28c3648cbbca6b1ab735feb5d28fad6f4886fe0a6596283455c4e096d1d4b7fcaae132109516378f4ef20a07264420bba06f19ee45818c4935e13b6b8dcb9ae4a89140bd96fc35a003b21b458a0dda150b439392cff8e59aa7313c3ac24fb6cc5f2ff5249bf18fb880b897e1980fb5c5d6eab9e19f7afb64a0cd515625756bf7a13748125b8809e72ed048c6c985c7d6f0421dc8b070d37a11e0fb974b4aeffdc43efe394300f97fd9636ca9ad42b48b383a357bd92f008ac98aabc21401ac7fa60ef6ecc98bddd2177d870f8319c03b221795113bc4160df2396ff5ae1072a15de0e244720602c1dc24bf3572d3a6fa8c9c0ea39735424786aa02b533050e15c6ba20d816565d974c202762a49d3ca8a35b3e464b712af2285dbc4265b9c89ba22dfd74219321a0eb8603b147a902c254b902ee607888c2fd476ade11dbbe80b7dfe81915099fcf5aa8e4c047c781076835eec4f05bcac11069d82b47d7088530a68e3b26d404593c778c391b3126e89db6fc612e2682deb56002e818ef1b7ac7ee06e7b65e92085c3427bed7cdfc63b78baaa81e01172f5632a2c08c25c41bd7a3fb1ae877789cb054ed5beec870da079f9960fb23e54c1637553bfbfb5031459dfd37208874029af980b6032feda5dd2b07a2ea058c50ec99c817754e2a978dc29e4282d3a152820ad93a3d3f200b5d7bf9442612cdb27ec716bbf28c02819858064b860438f42c56c6ee02c41e75a2bcd63c83d1356f2b130b35d48689e12c1e2d153b640b9e2995ac4f1e2f494341fc8aad0de882bd4032a27214529666946ab0440dddbdaa10c1753afa48e08824510c25b6735e8cd2736a1b4a4f17408a89294dfb846059cc2bc4ef2e69da30ab146ccafe8929329f88a72c16f9b58fdf57135e5b13979ee5d4fbabc6ba36056c9cecdfe3cc839e4cc0e4db76e438d92690ddef0c6913c679000e8804a83ca3d84f041d42577bf64975dd06a59836fbf374872d7031d016c15fde3260f3b67ca107a40d054f9075b07b3adc9e244dff370c3089e099eb417d13408480ea4529fd6562be560d1d746332e983156fdcbac4354734476ddefcd013e41c3daedbe4803494ff3ef663e33cb75d23790951b7b85f087391b9a57fd766b9cc6b1462acbae7789e6f797b232d6b11f115c25048e44c71d8bde1fceb7e945b303475d9eb66ef535a4abd6997b359f3b8840f605f32b377a3af5ae3128fd609e17c76679d541af49ea3d76332ca04f5604227cdaacc7b02b297417541fc8735b7e472bc1836d74437a9738b244ddc1a24cdac720c182a1ca8539953a860b62954c8a1f56cb6b38c3d3e956a7ecbf1ccf5a21624d85ed0565de824f51d1d46c26b8fd3fe494c2a82a1c69e36e90e97938957dc47d3ef4f4ee632e7744b0c7fd27a86034eb7258765a553a0b57fdcad1e9c65d0d166bf9f3d34ac86a806a076dc09090b3e616bdfa2e901954bc36f98bfb45e6c0452e080eb35f6edfa60280cca0c38c106b2ac23bc27fc363e52633568991172f0e3bb7c25310d33327f2e73bdf1a7c10d2bf713225fb38ae9e1f39198377c005ac8ee5ebaeaf8f3fc76b6f3acf819051a576f5c2259697e6a50f3572b646d327602c70f8ee1753337e6ea61f3c17e9712c5d1c831e6350e6973d7dce14e1fbc740a50acecfddd6b156e3635e8f37525a387a3056ee11b374c5865839b74bb2e4ede936cfe08a2780482ebec3ff39e02514a041449244cd64862faeedfa362a1e53672fcf4194bcf58e597f3aaaa0ac5d9d59fee0d48c361a8a624282267b1718754e6f6a3343c906897dd7551c98c6eb0a2924b367a2dd9cd6e4ec0f481f85111ae6d8fadbdcd24537ca8751cbc0b70e9d0eecde3e76f53bf90fa3dd3e6e2944ee894541b513c13ddecfd21b493bc4e857a3f9492e06299df88eacae545bbc82122d3d81ddf1afb9bfc04c93d9fe1d0b0da9163ef1472898c910b9937a591ff861da8831a4879c5cf73e535f9e371f59e8ebde342a15ad586e6f1865893b9420e6387cdfca925044bd1c29ef88d84b901218c956a947058f8a26df56c5ff17a142246fbfeab03d76e738cbc0d974a61c7dd87caed70aa1bb049967b07ea3de182e6f1d58a26603f183a2f63f7792e1251152c461e20b85c0642b8b2dc991484be60c6a20087776e572c14357e3586f71389e81d723b4ea14eb33188e9f40eb10b17afa12955de8bef28f91c087a0be44f5eac58e3091ea5e4797b8414c81fb1421eb50bca7efd75634e3fc30dbdf792e944569a078665c99fafb62a9f6c0f0c3bae87bcc45ca9a833622d48c52b5a97d83e8efb43932c3ddf54713b65fdbb4df4ea8fb47b70e11c8f587d6d0016226e267bb45ae037ecd4ee05f9b612220c9e831b2bcfb314bed8be89096154bd1ade21a6a18cb441d749d406233e2a4a3ff7b731bb2716beb13d639e9469b3c55893a2345cb26efb395895d6126c2f19d7a4c35be23b282c0b0bdb38fb163a381f7dfbf305ac8099629f71b3398befb66a43db9b0d181688beee7f009224f355f6527bd913c2d1613db9e0ec1f876c47e87347b1cfff5156d769e90d723d052e6704c7ce8ac3a97b2bed409f796f80ca9c63511a248e19c2013ce0fbb86b4e7d13d2ac96c318212b288c9a66f4e081f3c3b42cc0139cc9a7d9d8a1452c8366d50cef6abf0d4bef50dfb164319c876c553f178da84892061008e0a2e285ae0b6e02c4c43209d2d0462357b0773bab28424016520bee59ee0962b01d486c1341fedcd2ea580ecb90b92a93971fb976c4788e3021fbca1b69bffeea8dc67b3045bf11899b0eee833c06b6afd274d92ee5dac6b7fdd7b33bec068fcec5cc00a11528c5e27e634359210375ac8ff21ad1718a298e433db7cea760eeaf0f0c5b646bb9da5f75c1d26944081c04efb837fecc42a0852048a6f4d9e176ba4dcdf824b27580c90359de6845bb208942b2bd631fdbe19ff192585cf80f4d7c0cd8d3d6a6fc4c14551843084bb840d2f8fb84ecfdd61ecd577bfad853cf982d6f8bcf56fd4f86ac1d154ee4954f85d96e05f94f8bab249d0b49adafb110a8bbf153420b5db7e2fee562e7e1425011b0f89c6930d3e282d41b7b5c60a453cecb6bed0f844974827c3f53300d469d7096b256e55815919149c9625b5a0653a4621bcd9b5e410a4ccf7930292dd6f2a7885b44ee443ad009124907f1ad1197bc15b3e4c447e47f16f440dd6687bc2f650c5ded9f96e2002d8a417b33aa6466d7b2261fb3c7359493c954e271661ba38d8d5534faab8c85d0ac4fe73c2c8530764c20e5a249ac03b53ba0fbb06bfae3ae0e2a487e193a74eef19fb4bce52ccf967933ae69b84baa659d834d5fc7a9be591214cd697d8ea318f087dd599e304a8b88aff84cd555b15611a4f5c58e46439a2c14487498fe4c51db9415fd049f8e0c72a4ca75988c15d52f521c0b0361ce6d2057adb6a1fa14f9ba1a19d8844fb2481c46c1046fb4ef9ea4a3d93a9c829759dd5dc2ac98a47de5059de22a6c541cb6a077e56a587b219dff5fe4837d79ec67b870f827e7d21bdc85df4105f062bf4da946fae6c149284224d693dbc437e7ab66682a533ebf9f1c37530cb87091adcc516a4f5ee58b9c1235adb8075c9321ff74adff8b9979686932e3ed67aff61dedb65890a3860965418c6348483e59f85d02509dd0574e02cc0f95f8afb5f5ded747defb4146c7c887b6be4a78c76097321637f4d336cbad1829a4d53e50be355b7a21a9c3d8b4365057bd6fe7ac3cfcc4a214d6a37717977d4c9448e74f7b775a42274e8aec2d20b7dfd977997d7b1a86a3960b0a04c7b05bab2f52c05188bd1cc5f78773880182cdb15a82fb1644529177b3440d8e666cf446a933b7c62e4980ca50a6059721ac32b57c72899c96f26a734cb978cfcc07dc417a6a8087b8982ad771ab698c35c8d5ccae5c1380bd82a39aca6e1c412caf574c9088a0ca525e470fc87b3eb81d55d2aceef1088a6bae2f99c6acfa37443582a74721745e2b7dadeb3d8a6fb90e7b13e4bed82f810078d921726561aea473cc46084b9e2f0ca4121cba45388f99cd026f4a8a980ee6eee305aad6900d65f1b20c59a30c083de3e97de0de471ed34f2c16d1223ca5bac2adb5c5f708d079ae4300b864e20d08d947ed6f082d0155cc3d636d5da96670f57c56eef6992f012a5d9cd852c9cd7f58d79617125375115015f9e715ea0ecaac54114daf40ffdc586b662b749af2ef0f09f1071fae70ebffd4dfc3ef62813fdb1e59514586a8d94b4009542353db805ceeab611a5c78c6cdaa6ff2bb5d562c5d3b2a8e8c25a068ab226dd35cd6538d5708e0ef4f4bad9a428460bb3679e270f5537eeab5a719dcf54c17cf0a3795981e2ea241eea3cd4a902cd3a73c0060451f2d4b74002dbba6f1845b639f7aac474b318033038c3aca188943fa7c7ff7209a982240d6ac22197d109bd33319929e19032edb0d47bf4e634af3d916a6091987def2b7b4e227ce5b57d85128f40cab1a81c9b68d961517efd5c94baa0b1f022d30b0b1449cc7c865e7d1cf654b085164f5f9f2803216a7c21a84aaa21777e8a151467fbe44b9caac4b68d4b5565b85af7dce667523860a7a189d9da595f0b53c7c8a25150d274d9c7c706fdfeccd691c65d492204a52913b34db81b56c6eb6e8a1a99601cf28cc00d8e1df9e3b00001a5ff4fadfc82b42056a36a1b04f61583032ae51746aa04d7366b8e2f5f035bc8942713fd06eccfb092d0be928803ef33b976a0786cb4f22885f6c25395313f265bb119ba1fa11b712d6e10920693cd774f48ede79806abda35f66f27dcc3a135360716d217acb82fa7b45b0eb5b1c40dca9d3b6a4f08ec197267b304a6287179e820156fdc080a22ed6d3c69baf44f5b339c8b6a7a78160a29426a5f2417878e8d72b0b6c0dfe780d4a64133c0d8f8b3bda500edd210b53445f262fc521c44ff1e4af284ccf4ccda343e623b55f8f66a1fee287e5ba13ee0faddd87453d77838408c3cd4d3d0325b6ab428229a2f91b0a3153665accf990334ec9c7bd2bb47a064bddd618c496e583ba51dee3f58415ee01ee31d11d0a37a5d0793354fe7e2687053ea38ffeb972668d25c0923beeb4b3b4a1303378cbe371b651b2271bb4a496a1773e66e9fb11394a7cfd76774aeab6834ed8150359f7e9fe6a559c0964edc2946e8f310fd97f8c53a660c963885cacc8923b634a1b313d4970b04e9947a27ce73d279f0bae5fd6a55d02d34a8fc204efd2b95bbe90a379a07ca551c162bc8490c4f300113a96150ff216fe4cb2338382b990ab46e6539b265c688e8930edf554dc7fc66b6c660803ac420bc63dc685e40905b6116b0a2f2ae79f52ca19818f8b51b841247a2a293f280777e8a619c0a31cfbfdd4bd96a8672f55d86770a58bfeee24a5d4a26c5e1cdbf431aeca06a64e460f0b3147420039c86f9e11a33903c9f39a406b2dc924e910fa59707b4d161ec08d856f9087cf2d44f4c8c59e826fcac645f540a9bc25d10b2024a33730a9301943424e6696acbbd697a4bf058c4b4d365fb4e076f14776b406ad91e4c642c3355dada1a0166938fe1d4c8dc5680dba85a6c6fec7934ff3b1a6e409372bd523f16127da7c24583070036be56d06ebec2590f9c52f02969aae2501482288bdd1ecf635c0a8a9440e0b3ffacefaa63427d1bb31a608082c87d51f2eb35a21cc07545be54a3d9be64c379086e5b05cc8a70b260a09835518c6544ccf6ae959a50ffc9d7fe3f6b562021a4d54d9057259cdaa16085bf4103b76c033d96f5dfef1037b46e0a98f216f1abca2970b32151d420e679cd230c4c7fe7bb3ad99fe33312d35719a4a815f27310f224e7481218c46866e617a5f435caac7bdd12181fa7c1a6cc989f895e013d03796223e613f661242c233f560c7a7158467fa9110cadadcd0bfdd5be39be29a845fc1c9e50f368b78799401095a78850d2bf4d2adb41c30bc7dd3813f4ba2cf84040ea34c4c1dd56c20a7deebadb43e4121aa66fb8bf52ed3ed29a8b5c71838404ab30612689eb2c46b2a1ca35f1284352ea0c469686881a3c24d168808aef29b1579ae46f80e5c0bfb0e8c00c92b2207f496f9cb89091905db5eda8f17a5939370ade99a9ef087ad81676fb4fd549c1d949d485152dbf97452a1803524e226572b6a5387b30b1740972befc407dd50bcdbfeb92af8e4fc5f40c11e8e78d9b70ce380815d455e49029b175fe95a667308aaa18b6382ada58e4bbf15b5b3253b24ad1eeff20f201a59425eb798206f3fa1cafe8d6d69a8eee1bf7589cf3ab6869a70ceefc88b5338498f6639a1b719d0303a10e5651da674bb91cb2d05be88f0e4ff88a027245db3c0d70db10a8cd728e91d730699ea24dd9275bf52556643746b89267a9aa68d84d03006a5783734f8c7b2f4e88fbcec563237e450b77c3762c3d0ef1465a4cec72005c1fde70276b921e3d9546509dacadb6a5f81d60ffcfbed7219c31d1d9818ab83a1101ad15c8da7fc2b4c4de616f215153498dbdef475577bb1359736910538d7129dac9edbe789b203bcf97c18de07ab7ea86f0bfb801036ead53ce291430acb4e27d115dada0d76403437a7f9f679a12ba47c52f241925927306373a09a6c7b9267b462cadfb8459fdfc094f334c245c5f2ad3e1f2b5971a7fa39f601cd8e9bc263d63dbfd2ea7c7f67ec5f3bf1f90994423ea2fe7d9d6a7b0065c8817b3dd9175b1e01333757f869c1724f2924e022090fc0ebf0b423005109c7400a0057aa9de18382c269e959945f1589da6860634f97d9382db978265bc2b08b31fdda7a04b3ab2f5d51b0683bb3d054e1d53bd6452d5ff369d817f6295259addb6b3e43d0f030194a0dbc298a8a2696d0f87b7ee152f806071093cb7fa1e9b474379b39ce402d399c9073605f2c90d595838aa70c2fe38146338aeccb081aa19d895502f50ea2c9b50193fa3dd721988891a5c976121cb740f928f3f09ffe37508d3682484c9a883ee752603eeb8ede1ac2d2ec37d64b4abb82e46003f8b0557023985ff501f9e289eaf18237e4286bf2a10fe72e83f373858e609c048216b1810bd4e5e05f445ac439a8cde35e9b7b3021bb0e5dfb18ce6e7df8f3c6285d442d7b84f893be464b99d406da318d78b65dd83b36d75a813e1b41f034faed3d18cbcc5eac4328c8e3504a4288240d4ea280cab938461282821b3e33a6e85a66e16441b5ee57b2000eb7828b8afad28ea4f494cc503fdc578d0c5967284b4586036daf2aa4b04f014cc440571d4ffd7ad6a54079cdd6213e76e080404eb569ba94371592f75130aeaca4bc6030385752bc4c02b6130649a72977f9f087c11606080486d63032299c3ef7143bed8d82a035bca1395a6704e5b436ae3ea8992bb8ef2c766cfb59d01bec5b3d284f473f06b1d42bbaa4da9125d6785b221b3df57e3d67a67037900bd58be59f545fde9f33a28554669694a4f14a941bb191137a5c3c2a4c0e29fdb8efd69096b62c5b173b7b7126da4e07c5076e18f6014694d93213ac2381cb58b4b1de9509fdc879e46161de1301946c35ffcce419a15ebfab74fadf388886947bced77b378812f379a2ed4e948966f598135e43dacba153412501c041dc06c45838bc425109eada7232b77931f624f82eea5758ef602974b6da5d3df9ecfaf21920e0a5c3a3923191b5680821afc3f1c92ccb6acf4234cea38634ffd4ded26d3820448de58e19f4067dd24c9ec46f702cc93115bbc5ffea745d745f1cdc515c8f8f38bdbe1f897b1bbd3ae231e349c59bd34daebf831423011caa520a2cc12d850f8cd28acc58a9750131861d79cef6472cea5e2317018d2df2875a7922735e37d1dc8062074f2370374c6f83739cf26544742f92d8ad156181b4e3ae851222b453480a9e57a91624422690c4123a5e6fb8dc130d5638a1f4a11112a2f4df2fc191cb00e215e2e6547fa93d393806b49a3d7799b731bb2285bd0a490cface4b000cb6aee05571c8e15bc32874637b8677859da2728a527dc64e3ad697689511ce6f5491fc9fa1ae839bcf9cf2c94c5a3023108d6d1f1ef38bc23a81ac438ec9218a4b7f2cc278afd6cbb0d149dea74577bcbb31d87f4ea0f0715b7136d128c503802b28ebcd3e4c3e0a7f4fbbe04a57ce7a76ee928b98a5278bf20958d9ef4a7bc396e2fda23fe80c4f4675b3a028b8e16b31932b4cd41b89ad3422d3d41cacbb3e295b09c5a2bc8c622dba7a76e27bd88f2d146c7e4ab1e407fb6fb249795917d3f84483b6508b18a43df357ead44398dc79ce4dfe425db912dbb764941ce099e10c4a766e86d98c76243ebe0f4c04bca3307cb11e93d335a375edaf2cbca82f49fde95","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"779b78f0b0e284ba3ac14be43b73028c"};

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
