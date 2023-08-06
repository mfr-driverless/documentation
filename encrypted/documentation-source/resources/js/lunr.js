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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"01922429dac1cdaf334a74c2653b967a22870fb14902e89fe8a22fb31aeec9d797645a3a008aa08e9cdecd681330b68d93c9b93521fe719cf5c08c0fd7d8c4a2697333e2ff6b007e1ea4732e1591f679f36035a2e039b179377903072ca596e20667c50f6afa6ef32476aacea116dcfbcfacdf08363dc54ccc74f5ca7345c162ac801e5e6dc45ef59340b5e40c256995076cf8277349fd680678fba396a5c71ed8cf9a70055e7a1b79dfe1932c7e0540524d5e6720b11a0bcfe6c4bb383fd85b57c4992035a596c4193b8b0ad67d5d79178b3210241e710dce877c03cfbf1a93b863fe4552333da681e09d781b58ff2549a00c22e0b5976c9e3be608fbb23ad9ac513262c148b83a2ecea12ea1d71841dafb1df3eda71c4e7acac7ea427c7744039488368868460fd20b73997d6729cc9e032af049b2df40d4dbb6d7b044aa0db14ef18bc40c3360cdf4cd94858aab2292a8c58c9d1c4aa5f1e1e20bc82c63ef590afee0e21c4bac1708b5c6b7533381f2c1b9e99a0be3699bdef1c629ead758dfd7e921a94b7bab046944e62ed08ddd28c005d90d080ec300483b251c5a60cfcddb1c7a7c5f1a8441f3683fe9f9049a701e019c3136de18aecdefeebe513873e80b672ef4ff5e6de2dc2c53f31fb42f7c06c1f4191f1b107810452ef6e903350835bb6d08d6b16f67a76a595013d4ea06f8722d3d8ad392d0af0d16e83186340ba5487afa11c1846b6c5b9dcd5c2e2a67e6de8c4d7e78e6cc42761e89bb14458cb1b4d10b528779b4bd8e16829715c8d2dda49da3e478535cd3cf3b5530d8a7f3e0532a29ece919689993e9162ea4093725405a4fdbf2c5e377818df6fdaa18e6f9f2d397c0d49d3bf179cb1970d9b9750c87f32aabc72d09591eb8dd957a177ac7bee6b81c434ed1f3bf848fe716a242facf0f751bdcb9ec7ebc866111e10b6166600a99ab392fa15bc7495c9192c725ba62e59bb1b18cf6cac4ed631edf3287457dc134879052f0ff6a49aa42d3d2edac8b93983363414327099038e69bdfdc609e00caed1248a07c80dbb36f064e90f4b92713c77df4ef9956b53879e06ec159b2a357419e259f14e471bf59d0705f09d3b71c4db80b8d4810411e3751273cd5f307286e47513bbcfe38d66be163e7dc12c5a3919c0cd799f34fb562c23c9e90a0905eeaaa77a5184fd97dce173c1f8986f653ec5e3716b57a95ab0827df5be51ecf1b3ccee2e9c7e9ad99c56ae8da61d80dd7a02b16b52e83d96222c4fe47605dd052995047ae6bade00994009dd3124a9849749c0b6e1e342214b6412dd537823ff1b086a55c2a687464a4c608bfa76d2d35ef02f28fd273f29f67aada2b1f44b77fa02acf9aa42c070ec2f5d92193401bb70c888a072b2171b6bf2854e7d1d8420bcd0cb54eb2ef9948abc8ffbb068f2f2e21a94f2cadb89acc423e3dd49e61c0767a6eae365a621ed408a9885af59369e1a8e5daa8101a3c3e2e05c26f92377f8e926ab974288c502bd6c92d4ebfacf65fbd3d95159258f46d3af42418dd8b6d4cad6e79af096b3ac194b01a9f3b5c614f4392a464ed080d9361e58b25da745a28239bddb29d60e2f35df940a3cbe1b8a8ee7106be01783215dce6a7fa0eaf6bb2538e6f2613f8fb6c1f27c5d455a6ae272ac1a27882c3713cd035fd4ffe4efb3c75e9490e288fbd5b0fe80c7a2cb1a167b34160717800155b0a6a839608da74138522ad40ed777fe7d34a04b9015a9e0545901e8efef95b812899af65503f2c893009073460d63156508346297f231d166528b2964539f843c6b2249f582ecf429b47a684daf24a953f2d228e6b6cb127b41cd332aa6e71de90437e5132d0c0586c49a0c70d677babafdcca838e58c16813ac5b569896eb87ab25d78d2bb9be466edb74cb356e54f5a7f04ecc02b4ba64110d11bfb4263924797c4338fa7514d5b6da214f03c4fba2a02cb626300ef4ecd72447439794c69cc109d2aabd29e7f02bf2b811d772e768be89cd7dc287134e01f948efc52f8c4924fb679747522c3bed3804f9c02c6509b01ba921416a1b913407954e90037b6257609e5d16ebcae232dabd2ceb1e8308be70677dce430362bb0ff16f943e8671682637b105cde5ee7e09bc42610783f9d3ab8033380fa113c6e9167b5a19cf35225e51d759dac26763270ad117feed054e250999ae7ab711cde879e070f4d14498b8344b94897da0c370dc2210ce4351858fd0dcbb293f350018c09944c77fe4d32108e6b52e53e973c1d5740a3eeabe081c8fc214342b327a0ec0cca731b7b5f6c6c5c9697544409a9a14c9a5155eeefe6776cdf6bc06800849fe74bfa238ddd616a46b4b104794e3c3ca3bc2792e027a5141eefe1c41f5ac6e36fd5c00f32cf8d3f1dc8d301327d13f84a97155b6917e3e10e62541acd6575d921c86d3d522ec5924b44386dfb551775e8a03cf22a949444f9eadb8a2d81be36c7c57ce6c8fd5af49a8d26fe35e9a62a32a12e234865a3524351f674fce5d0b6956b4ed1d2d11f7a1f8005bc55348a588336e17f8d154db2529744ab4a0dbbf64b9ed3c94caf3a202b3168f1c04b4b94e80d7039aeadcf56d492d4e3d9c243e177f9516dc308e8f1077069ec03f365be77213a0ee859bf1fb2e17f7ff482e4ba254cf04dff30c30953ca5e53b5d016eaa4eda96d95cbd16c3e660199f63a37b27f5e2407ba381fdc1c02b575a29074b3f493429a657b3064949ef57ef261ab2ab23227fc76994ed80b4c1ce74153ce20e2de6a11f269b3b47ae156c39a6cdbb5d19ced4c0840a672c82c53edb5ec78b207205d2b80f1ba29447a3bcd5850e42934726ebb283a5c3756910520d393254ba8e4339d05c9cae46e15a24b1f21c4eb65a597fd70e69f18000fc69375838d728eefbf2afe9a867091fcc7fd0b19c57927921a1f429dfeec484413807b556c9f6a30f64db19921e04e02c525eee126a0bccdc324d47e10d0e1452be2fff4d46e807a59ac72d875923623c652648ee56a624904701a020eb31a7c3026979ea9bce1b9a884f2c7c013de30a76927319f9f02f12b7dc20ce414b5700daa8f643a04422538469c99d349f0804bd80a4c6f8cbfb3e21eca98cade4174cbd10e2f3697d54e2155a90885cae6643cf7ea9b15891be5d8b1c85176f4df577562c7214ff1b84553f6b9004dbf3192beebdfcab8fa11f22008ce7ac9883f93a6375112d54ffc8889be76372a67bfe9816bc3fceec9f87861e208a7429f5a90a2045a0080ed91382ceb78503e242d1eb20af8dea224ba3a93ba39a7097f2ee6914f891835d134ed8dc495d4022df594026b7bfa967912cb45ad8f8b483300180989b079b902f3b2b7719cbd296fb590106b78fc7001c7a8cd9af77d356f8ad66dac8ffeb57d1aea41b2713d3ab74e36df56cb809a3e268e10468c4649529b90daa28c64726aa8793de57b5d19db8358d79e06599899ceb2e78a36c0b9e25ec608a4d229d6dc7ed00120f160ddc616520eb6d8e6147b20ad2f257ffd5dd9c1fbff921b8f18390c8f27ca926ebc79dbc4e56d235a675c4b2a148f001f3efc969d9816600d0bf03961451d852a09a18a8ab0a5dfd6a0b378115111b6ff4203b8b839d07a6b486429448851025b4c1bae040664c938fc15e024e312f147afaa32ea3e6c88969cb16eb23240908637e1a920cfabf1416cc00b00ced53e5709756265ba2a22b1d86c41bcd8fb7c5804c04cf86e884c09d758901adcdef5278d3501bd059b70e3fea4aee70d3086c6c2b6d2601c405410f11cf243e51e876630e65ec39366874ced015776ce3d89025e1ed02389db73c79f02768ab4968e180f29b65f3fd45f6756729249782c5c5b193c96a22c169d92704820a7d4f0417ddccf682e2ee3373e12c25d80d0b0b7622e53becdb6298aedc1a67ed6b5379bb536b5565e5829f705844b57004a940b6f074f5bde8d0d3bfba7d3937c0b9a0dd6947e855413b292409b84b4b14bdb9709c0db92da43ee4e00cd5b183804e2ad580b7db5c3c4605d3f8541b67cf3a0b623105770f373c3d492bf32cac1a84b86b15545f9ffc5a32a96ad4f1ce89bd8e32e0f6ae210667f806bf4c70769ad20f55416d821c6fcf38aa8893da504ac2c2e50e2da94a857140783e0d435a30f765fac498cc0d94954a5dfe287263fe0c28624d21288c340333072d73e4ecb2e5fa94a6db80b3e975065a355a6b9a0bd3b8c35d79e9f655f7b99118815d9b98fccdcedf1c4e14b6691724e21e8e6f8a530f246adcedec5ddf58420fac5a2518829069e24d2465bebdcb34a153d6606737a3b26215ff8070fca7cc77064f79823e60df6e1bff5712edf4a62eca6d39c38ce9c5439d44e80882654c7b7ee263b13b160c11e287d54f6e2fbed7a48bd8dd0ce492b7ccbccd10c87395630f5036c9ced12374f2e6c8876c5ffea653949b39b8b68833fcbc7d873435b23306cec39f0a92be55894f9fea34539d66b5b4489da92666d845eaa160ba2489de462a9da165d35393d2d55c5dbd500b7e863349a1567de877cdaf51d856d7bce08c9fa92cffd089440a356c8e3ab76a1ffefe39ff72eb5082ca3ba9542384e800e05c97f3767cfa2231abbdb11baa2856ba75de6456aa729734885f1459d2c81a5550e55eb13b81e470d0771832c5558bf0e4d91a696d303971b3500afe0f2576b7b4b701b791d209c8f28dd2dcdb0b3b09b8bf59c2491b6aa9b35b5824bf295d673e55ee60c6c24c50bdacf79899517ae42a6297174d9b9349a2c7d04c9dedc01193be4d101779c17ec35ad99b21a770e07842ace012d350b8f6c8c7ad31af543a1bf5e6642131b83a2ed0bda992c35e6abf9b877f9bc7f9add1480b876bd5dff950296c5b9f9afede6dc24000c192721072f1e25b2fd1deb93b385fb66863e2065599bed7478f2b6a0f774b34f0644d75f9ecb96f6a94b7e11cdf23e920e3dc058835054aa7484e1672f3bfe168105d4a9f1b6097409ea507d3067c08f05252f9338a27d1a1d4374452bbbf801d47c386351b36cbf0e221cde37ea67409c4691dd5738906fe562038ec0819651a9537256ba69438866a89bd21dfbd29e8f46e654369f812ca1ce9ed63bd62743a12cc4bd845ca53c1555bc691bbf09dad556d4fd4b14e9914b3d77d22f095bcf8143ad9a5c7c526d57b6841adb642bcf1fbc66d622f759e30727e52cd8aa60b9b0eb4505e7c2339fdd2908f6809b08a9a9f925d3f472b461e8afd095f39e9ccac01065acccf94d94693601cfd438b36c804a551ee1e0989b447744cfde7f800c49e5bc02abf18e7994369651c69f2a4c09cbc7f5913e7acb2c21d4c5a34a1f5ab862dea6347f60c5235afc3323751ba716451d11b529af27a2466e7f7092c7ecc2261a2b9b34f5d729cb049ed82d1f7876f69340edcfe6ffc78c703bb2e12233585926ce17c9ce0c1d41d0fd989c650a76c6dc796f0f494672827a0f45caa17f1b2ee7fa564ebf1ea4a1acd534da55938e8cd3cd33ef04315f53881ba0c1ee2b9e086c94c1700c02521ff7a17dc8760d94860a0524e38b53162cc34275116c51ebfd4b82e31d167f5c99a0c558a1e71f1170953aec44d4bf1afda3521f71e33ff9823a1f3f2cc14e00b3f91fbbe300a6c28c802837a963cec094223e5124ebb832b957516315448f23191d5ec6503d8041963297a52c62c3440c75bc792ee0e0f5e0ea76046890f15f9686d8108cafc71bb0a2bfe16ed3c4937c1f8244a4d17dfaf7c74910b58d0dcc9aa9e1a42f649a48a434373fd305e4cec176370cb6d8a1851cbba9f479934ba73ef2ea29522d05e64c6529f46bf9f19708f56fb68dd0c526a7609e6f007780085ed1a979b9a8cfeaea0c0a42f3e64b2bb23f6ef15a8d81f9b27e699b54387ded31412b34ae60733c3b6409c0a4931e3decf200ccb076e162ae4c19a6dc839679413b6b497fcc978e80879981527bab8782e1348699530d99ca6f023ea4d1ff4677d49827dfa36aca27231d3842a68ca8ac0c515e4a1f3853bf9e6f9f9dbec04a22be285570fbc2787356b5881261f1b0920707b841558c2727943726966056b32e447c1e5b2f28a1ef8a38f8c9aa84c2b8eacd3eabe612369f78242178378fe71ddb8fce7dad6953c644fa4513e3262d9f5e12cbd6988f5bfc90c3300c5725d5ad35c713c89d1e86021f55afdacf7e392f93a35e50b9b9c8040fa6742f29178cc21653ad3ff2d09d1ce227f5404b4afedc98cfe9ceb9f1899e0e780eda585c809175b3b80bfb2c17a1258a8ed47213ab3490f4a0d60631a25f1698ecfae08e3904a72f45ff929e94127d42d46abda8bfef793d2e8fae7fa93c7f5466e630447069d1f9585a400f382bdd63d02844b96221f0c80537a12a9383bda344f62d1a9d87b6d9ea9e9edfa49691c36fa819c9ad006a3049bcee1af27716e3bd539e404e28d647cdcb7033ecde19dcd11c41db09aca23aef37e879b796840bf1318e8ce0d991e6d993f141a11fb2d5e855a6b4c17c4e0be3593eb655f0b236bd238c537a2482e8f9a16a2e51af0469559f366775eb173219b06df2918a6fc818fd3165e5b635d517dfd8561220e3ec0c3067276584b0adf922d3966d32540e588ff24d30b636d367f4332314eabaebe49b55c7a3fc288d00910370ff664ed11d47c8c3f97db7d8dbf6d7296d5ad4f3bae1955109dbf12367876eeef99915c164c47018add80ff5fcf73b0ea7e30af1bf848b4c6fa67ecf67a0fda75548740a5943979ec4ded0ffeb1b77aa459ade1274e180eaa398a555dde393f6a9e92cbb4a658fdbd2537910688cffef3b246c942a6a7f86aea9140e1489d1edc0b6559a01b95dca3435ac06a646114a835d405864d3db77999b7b857fb59c717d037b9a502ebace76ad8ea42260db95e79c333a053c7ec9deedbe6f23092ae7a4e4d3f1597a455973801c829f88c66cdb1174c7653ab4fbd38bda71e1fa772304f5165c7dfd8445bd039379e85e41d1fcdd16fc0bbde611fb3d3a7dc99f3282a9bea960dde882b92db6622220789b6df124fa9c1c7cb512aa965cba45b6c37c9cc57fa3aa763b8b0489c54d7fe75c0ecd42475f7f37322cc5d4552c2d6d42a017337437f39f317fb8833ad6350b2924b0aa78823d639eee39499a4014d475c758e7186dc95d867d810695c02b3f055a9f7fb3a125d142ba2db9aec7f86fbc51f1596539c5a5597779e64de6626c7de12bb76649f14473703c3913944dd7eb73666a52d1888aae1569eaaf3b1c7d12fb4163cf4b574c227b3c3a2ef72bc8470455f08a0f30731a7d8142661df113362f4d312c1257329f0e1b625053418173fbac864de6204f6fdcd66219163587d2a642d323e04ea1106f1904cd2b15fc8ea01233097ed37a4302f8051e9a4b46b8ad5e862f8d4364cafc6630e939f84a0c6b7e9204d9437458b01bc83c71a6eec5b7779c9f1f28c9c5dd188b09d2bd8084b6002eb63bf1ecf94742157ff0255c55f9eebffc3d331aa521ef505949d1040417aebdce7fa38035004b64b05f3e5471870eca5193f525ba855f6266ab36c87f5d8d8cc2386e82ad344bb5cd9213d898752c3ae0f4f1dc94d7c0307df716ce983fbd5722d98e653155644f5b604204fc1f25e107842edd06826e4a6c41b5d0f6cb3939a894bb4acf830eb08a38541dbc2bf1d3e83dfd051fb315d961dc2da9ab38582e486a8146d6a81d4bb05f7f713579f7b269fd4f78ec91bf052f53997e51168e82b9a2817781be8d80596d9df9bc5ca1163a50da39f88fccfacd7c0edd5adff57be842723cb9907b5a92ef8f6d4e8bfbca3fe44174a84d6a2ca71468f7d7fdb0f805f4ed1fdb92e4085583104fa8b83f9c7721e34a64aebb7c8851e8119173b62659f66c3c7de5bc8f65403751e2ed9ab3b4fa7dd0992c3c69b70f6c5b7801d2df96ad6706e0575451d704d4ac1c4ad5243128ef7a4e77c96702e9fe17c2dd4cd42167714429d42f8cc10e0f4b922a8a32afbb9a25a7e2362636ad61f4c571c19cabae011d1beef13aaa78185f03dea41a1175e37fbc2636b7e37ef9e74a1fcceb55b5cc9c43ba20b80fbceddac067710b95032e167503dad9427025b469f27e5ee2f8063da24c8092e552351c49067380a380fa44c2c88af4c805afe46163545c4b1ac5b4567782fd244a4ac14a06b135f4074c70d22275f8a1d5ae85a2a0eba05f614bd4be3fa57882fa1fb74ff62b1d8987ccbfdb4dabb47a803fd34c7c0e9058cb5771d283728c8ba2bb03301ff6faf53b0d4ca2b829d8e4f3922e93b6e75489cc46f33e838b987810434ed643d36a94ce9fbebf768cf588ab041cf20b6da04e106235f87e841a6d66f3b21ac8a9d36bb87d110033030fcf240acd5effaf4db20388c7a2e1572ebf0600daf9d9d1e39bbdc47d2d9d9bf55cdc845afc479f347e1d430d870b6e0fe8e846e703c93c4c5b617891edfacb758f453586aaf06089b39f1425fac923f2d8f295b8a89fd5dc514dfe7c47e8a216434f2f5e4fb79e1de7dfb3d92cda80b6b9517762ac03eeb1022b94501885174575cdb946136c7884a1d3e8bab7cb846f9bf52cd80d4a33608783ff24d2ccfa5b9c6e76309f08e30e6d46e97d4e513246b65cb15264ce8b268065a3000e91d7bead7d377e8ba106db5db7261a87d52cd54606317055c84482e8d83e9ab90b36d419ec74bf004ff9083c31f9aa6125f47646ae948ddb83937780372fff4c5ebb6122284b6bc23c1d46b0e61e1e8b2935e850750e0af14fab69ab22cc5b0756cf6466b90b7d8693539e650521a505b5fbd794a61999193d2b968129221382a5220588fcfb699f0d41ec07086e601fdcf315f91dd6b5df708dd065c7d329884af848e195f5f42c127bc84990c5cc84e1afd5ab6dd6a5e4d9301f4dc52019aea75407590d3ded13cd3d0e42712536dadde1f299ec78d0e38de8dbb10a98394ef90422c74d05237c7d2f52603e44a272954b309ac040fb769567e8c054f7d0c7dd7731bb2751b2efe6461c5f9f3de8005a64052d95f8855daf067cf4d85a9e55aa485a4773dc35da3914b654d4e50f1e31cb21792e66c842aca52f8e04e5cce6dd3cf11e1a24340c7218b8e567d6d0e5cb80bf5ee44f2d4fe499a8fd33e2387653de983e9e6d5a09aae918218be313321c4eca159d44092932bd8f110a28c417cc9a998cb8945cd207312cdbc9153ae0960d291ece53799e5d25a588525bf0ecfc6c50750e4c105241134deec0ec8da5a81f9208eca354ec1394a3f67de6ae4add1628dbce3cd4a50c53a58a73fe65cafe7d049836462b9a339dc66633eedd19be2ddeb141ca7f4151003c255f8b2ff331b8afffbefbced5da308d34a04c127912c8cbda4657304547071331a21819de8f0fba446067c143c673b4aa4b74d89467166822b3eee55f8557a8367e7e986c14d96ef863013b7b255de3f351adfdf833bb9d44affd2b101880f6642ab0052888451ddade888ad862f214e27d28821fe7fb435b3f97c4f97e31c5f00f0bc6565358261400162da6cd1cd143e7fe9724f612e8cd5e13575f21e475c1ed28451a21c4335d74b79eadb9ed8e5987b7183b7f2339e3bf0c48fa192a9b65be192c27a23ade5aa2ff9e949128ac0827a2c055bacb7b7c90fa5157adba5ba3cecdc28e4625142cf0306385d77fe527cc08c703568482280ab3855863957a35eb1b8f5d99728120a6459ab9fdf126fd1e99dcdc150926ef5ce83e27ff899c91f83d95a1c60a57071b7879987f2a30af8334f5687020bfa9f1ec0cbd00170e50ed54007ed2329f7c50ee42f01762a3d51c125382e4877682077780983fb02ee37face8a110c9f2baaa606ce066699d1f9781b40f30611fbd5bcda59801ace8cc4b3504d824374c62c1a02ee1b08fc8258e77b9f4883bcc69254451ed549a327737465c8b9acebba94198baa2487f1f31b6712c1245ea02209d2163a3729e524801f670c2a6c37f81280031340272f4993e303f439bc9a8041f42b6d6c2ed55b4479ac8cf3565e7aae38dea520b3822eec05ed647b762cfc74aa4a2d0c6723f9e08e6fc50826bdc7eaf3cd2f1edcd58d477c91607ea696e8085796c9f726bbcd1d7271798ecbde63da73bced2593230bc25ecc615a7a2cacd1d70ed3c1c13a143bc45bb83a24cdddd085661898b290eabe5469d1737078944580b725fd2e04aa8ef84deb4491261ba46d17cf0c3d9619cdf423ea77a7892e56720f0188fe982e863c4168d413bbef285a81b7339d6855768e4c134badecdb82c8fb79919ad5cbb04b6eb7bff88d487739e2ba9737c84ac47737cc5dd1b9a8707c62bf25a60f10094b605a58d65b4f5949a4784b24a68ed3a95cc3aad9a2907376a3dcbae68ae1b7d62780a6e35b5dba6d07d84f36a901f687f94a556b9e1ba5f891667ba101d4b1d90b015a24ec364786312c691b2e291fe0ecb3822a2037437147ed5a575f7a6d85943fc8bb8c28fe1be067933abcbc42d7e49fdf1ffe575d3f74af5c6d217527ca56283ae19bf88fc26d5eb08e6793c7e13fef63baf4b8a03207fb98da04a1c0bf89e8b71625069ab96c7d784875237d1da9ef83c2ef9be36cae8e928f3c2786dd4413c40e6f3d35724534d64fcfac70f4b0b309a61ca5e9364b61195a567b1b7d2166adb411c0b1ca955f339bde7e73fbf5d3978cf0d340a6e2114f915dcec890fb1429a01c8e89bf395e3941b29a76885303260fcb493701907085450299b39f39cc1145441f87a2d45fbf37b606810db466f4c7a40449058eba6b5044bc826a225feced89529fccb12d3623555b0759e53b31871c052da7d6af703901b47ae84990373e4e8b16f521876067d8beb5b3a55e70a0bcc669197cd5f9adb45d06487982eb093373270164f9c3a09a2f3118d0f72025d1e2fc55dd2b3f28ee50d1a95cb9c19234a5b7350c3e985cec215144def02a65a3f4c7e25780b2b8214bda5e823eb7be1581e57556f2c0eb54ada88abc0ab24503c0320a444d644841033a929391de26a3d8c793cb435a003076ad3eee100ef9a603ce264067ef9a192de9dbf2a06afbb2fddb662c48a24056721eaeeb2fbc6c74265ef53264e5e74095cbeb4904a2ec386598bf08a34b155bb37190f25e7b8287fee6fccc5506e361cce0ee1f486c9b9ee4a94b455903285bfb34cf62230ae34b43fe9eda2f18256426a4f861d938e8263d375237058eccf9fc7ecb8ba69fbba3e2532628cca83928d339f137f25566b5d6bd3928d292fb127025d233471dfef680b15da97b01e14372d4b1b940bfb68f082b2656ca2ecceb467119334f80b0f82536eba72a3b6dd98f82eaf8117eaf9a74caf375808bebf703e123558d58249aa1eb9f8937bd51121a266d7c2a25ce68270a87be9006fb7e10c951d262d7000c7aec93a2e168ebbffdd5f414c09d19c53fc371fa87ecb0cf3026deae67a25bf6fe5cfd1dff1b561775472a22650e77834dd7e3194e15f8c2f9d7251f2ec8e725f73561ea7eeb79936dc4cbcdb4d3e6c2889bc85ef8052443dd7868b3b0a03b7b08edac04291163d5659cbbc621c0ca48b48af5e9a74fb1fc1f7d0e0e8624720f9d578abac006d9d78ff43e992ebfe3e352b5e3157dff3a0df87e881181194d157a9aba7ecc98843f62e5d80801f09e994526f381ba0d39121a0e68eaf38890c4d35ce1e6fd746ec6d9692f276b57ab90253533ca058135f36318637752820fbc64519dd276862d6df7d9145f21db88e88069acd6404bda547113508cd083943cb94db9d3e9fe28cd824234ccd4f01592e610906cdaf68e3bed0d94b8c8f49738c67d9392eac05b1070953fa8d885969d1d44de0ee7fd710d6e5341545d7c6c9d66abf9e7059112b4fc9e12eb0658cd5aedf411102cb83be9c3fbfe9cf1f08a0c0958b1302cf68a3a193311489b8e2c2b7dc8ae6232f75b52b7dd42c2d2e96002856c6ab846396cbdc6b3a698e63ba5e413512c1eba8540b15c8f2f1fd688ac798226f8599a58d23cfa1556a2484201484d84abe74310fd9069b6f516ea60d20cb8e40efa7ac9a17a067ef94e3950ccdb67c717ecb501b59b38873776613f40a6a9946c8ebeb562ce20b8fac06633f735355b57640a601568dd20e59158acb85477110a5a8d2fd9e253599f793b842ddb9a7c6f3568cd56aad3db81b1f677dd2519350e59c596cda371a7e973323d9c2a91940e2506edbc217654786ae23cfd92fbf671ab9e92aa394a2d3345aa3ae18500cfbd044fd6452e9f779239bd80b94e0d31228e7cd22c67c77d90c6207f30200719e361ce0269a3b4ce6fa8dad6517752e44bb47500ebdd9b0448631d2417df189f27d183ffe87326d7147a069e49116c98ee5e887a8eb9f8f4a0d1fde7fbadc94f153655622781da15809f7390b2e1a7be8a58a97aadfb04f5620857613d2b43a018f7d618da4c9547d1b361146f48a17516aaf4a7126c094d209bd59eec4847ee5909628e60b643289feb9a7a90b4684da51b19f64c2339759d20620cd5e78daadf8a34eb2161739e09aea27a2226493ab37c61c0178dd36ca3c95b56e407ae88c28a575e8d78c90106aaed358858c1f8a02a736a40391dbed9fc085bb7845dd778384a8c0b346ae9b691a3ace50f2ce8c2e7b2f6790c2acf2fb61e8a522b00ab4103388bf930b1aa8dce66ee14b4d804a8d64911a3f42717d1dd3e3ca3a3340b25788e576247eef968303f6911252e3c0e653212fbe2377a90e7be42a1471f4fe1d41d020b0630091b4acc94ec8d8fec392a290ca8d1da077ca1c66f4bbc5cb51269eabc8d3415f49cbfcdceb28a011a124cbad08bf51bf06a05e11ecd209c9a5b54c5db358dbc5f0cb49a35bf79931ac1a8693d87fa44651e98a64fda39de022564c37ac05d11afcccd6519fc27fe110bff9a6508d6fb44d1e97bc2933f96fc8bfa441f46567013d0f143826a4c691853ea11a18da74335a47b99a1e10455b123f905ef0bd37436af88b3c72455d9b1ab23e3dcb14e02f24a4e8921b074b4237c430ce528e965de3b60e980a84dd51a3670ee7efe4df3f3baf37a6ab4bd6f11d49b330e10411bd15964fc437a10a01ca97249cef9a47b6641cce33c3d448e7c222bd61a230632cfc39e671c21a11ccc17e286e7cb92a7394936d3a77bc18bc149c885c09d1302171079923086810372d2a62d5f4d30a979041a7d96fffb7f23dfaf0edd5b9ffb9ae9fe8406735957a090374bb9004fe30389bcd17498ced9679b6915d99629354812815201d9f69acbf21c2d863cc0570aed476a46aa0aae2d21193b02546599911178ff74aab1c9aa4f3a1d2616b21c248d3b7e31ac808ad6e239096c5effbb7c16771e63faef5d7ae1a32c1943e7893cd6cc881b176180f63466a6e1578bc5974d2bd13a171740531a8f406969dc319b028d41cad9e4c4e82e2a756e2f2c9ed7c66ed57c03031f75f59319472e203032964f937a26f2823e63cd7c1a42ffbf44b3159af3e2cbc0497c08f18f21993476593fda1a08bea5d7e456ae0ad10b63253b6dd7d5401ce84b4f6fdcf016ce859cb0116ac7ad0536f01cfdec1437418dbea7d343f3d9ef10b02f6bce34c36be35db8f24095a271d63141b2154070f72f6821435083fbcb1af63e2590a9ccb1ec346dbd159242c7ed402f8d577da8f0d7fb4370f11e07562f116ab3aa1e1d509216ccb743c42090ece7940bfa4d59d94e48db7293a91ac2f15aa5fc51aeea419255d81dfb130f6cca21679e30b464c850ba79c0385b76d375dfbd6e4ea5dbf297cf67546579ae1b6bc7e93db85fbf2542a6e5a9d5b81ec70e2a0569ca5682ece425d9c2f797d201b39b5760dab90be11700770e5f5c02647e9116c39778e17a34ee9adde869a80f9b6f9918ee557edf96e3585bceb572d644c2025efc5aeaa787210d73f6180fb466df4fb58f2317baa4d653b856f2fec1bb48ca30cbf2ebf6bd8d80938d6337538fefde035f9864dad5faa3c0e876d9d6b383e257ae98f1e1da383a0952b4ff29f20cd12b14ad63b46675dd4529b1eae1ccd1d63af8c7a11b69d5ec71c8205c5692acafcf817d7193bcca7e589b2328a806861241df24e8cc6afd90216f9810799852e8321a7ba27d6ecd9bb00846b57c7748986a9d656df2260d8241f2607cf04e403789432e44bca39f4ffebdd25163fb1eadec67f31d02b7a79ee12f021cfb5cc7f72ab45ee2d9844741b405ff2397a09f5957433ae0a5dba11ccc541b2419e9d3e6261695aa6dcf9bec50e2cb70c7e26001457f9442be118ab0f82d660ddc4e378189f2c8b2c8a4152d75ed2cae60e8ff78d205a27f8c554018d4d497d5ebc0bb64d86e23c40e0331f41f9478518c57422f9727732e425420c5f2b38cb43db95cd3385e789ae1016e44892af1b30eb1913bbf8638cd1335e2cec7b846f002dc6b7c4c0f75d5127d50ceaef5bc5d2ad5e404cc9c684aa53b01337e169b0dea508f45cec1e1ed218d1ff2329905bce75c908a2d985ba3740c4114b4d300edf06feab52573dd26684fdc41fcb278c258ddd9f06801b73d22b6e67c1d168619accc44fc9d8d7d65223e88d7d5b30a165b6c46acf897b9544d04b9a3c0887c64a436e9de67de19b4d09811c9e9e99cbb0eb7cb16422d6a87c4745fe1c028a26f5891be26695d2fd5d41f7ef08f72f36485fae1fd7140343cf4f362d8a672c18bff24dc3342d24961088b0af091543ffca76230289f8487eca44f68962925a1b4ef6625dd2fb02115f87cb999a6f3d3fd859617089a8a7eb7b035ab7f619bacf2b92784905061d3a62826ab592be8bc9a143b7505b1a2826d7e54f1001094b73e9eb55ac5afc60601bcb4e310a9ee13b65ae17fc8442070be19bf8d56ebbfcb5baaed60ef8d4075d703bc00b8ca13d35f3aab57d8da0a6fe0d1e5152b22698fa07bbf6fcb27df7d1e453071301b29cce134c251842be386ef79a651b5a849fd753a5b291fe8f62e4e0f131f0c02a57e2ff3e1e79f9626e7e536b12e8ced1e0fec123823b8893551350ff3ed49dd6ffda4a9739c2a8d5d6c67908413843219bb4d8cd201296bbe0c5a10046375aa9e097d2028eb4c0d403c0e63db8dfcbc92de671283fbcf6d5fa5b237dfbd60eea6478ac4ce9a714f496c0be9181db6554f4358df4b09df36515fdd8dfb6fee72d75378c1a9670b0b8350801c5468307872db76b69c92458ff028e3084c972236adf39776d2fc8f2506a4eb7b5c2c29668638869081630ebe1b085137f8ab9b1109500c28ebfca2e11e1a0917034196a9718673c2191d59241598967dcc3f55cfbda63a6935fbca373cdb409395771ad646fe9909d9370f46e8956ae838a8c229d4b1058ca62012e552c9df1a780052e9791d2ea408aaa7a0f5f877d191e6d14f44232d6b5db53132ea84f4d317b9a51bf528f2c3f997f72864c5e842a4b03bb3136babbd35a3966f306d93865cdb7e1619c3c6872f81eb8fae53b4a6f6947e3a1e8105ec6f8660a80c5f9efb7c4edb14ee1e9ac4574186d917e0423541b77dc1636afb4c216a260d61a652be208201b0a3828f0edcf23a37dd462f5df8b231f4dbd51675bfc8149f8d70a37c28c8819a656752e922a923140fb7aba36cd67841c34299a573c27493e74620301512727c9448e1f089861bc21305cc70d28954147c9954a5ab649a0be6f58e507cde2b38ecb13d175724da0daa5748e341a4023943ce99da1305b0e5809df88f7792ec2f31c653d7d0bf3be22e7d00e0b5de104f0128ace2afdcc9fc187a56993960f652919e79f3f8aec66adab221c1aba2cd665dc341acb6785f24401e69dbd5db6b13344b2f6cc909562b057b87c2eb219dbc0c79158da90d8f0b0a278a5b607615f8fbd2426c1470c9853cd770de9616876add8edf4f3d4193a9b5c081d8f8c79d5ed59a2765f3f2e50314551c9c7efe867c160e2eb8e2dfe9712351f171aee381abf9c5bc7374c12b245aa9a41cf8e509ed94ac5077d816f1f5d1d7c05d89b25bc779abc0149d855b6a9da7c3bdc4b0dd9a6342346152213a78a24cc41de793ff53a5215191c3da14c83a77e38b892e55c4f3c7afdcd51685417f1833045c3d9e4d34feed5280482e96101bd8cdc200c403b2cf4e124b14bb9c69dbba38baffd9a27b1d5dd7bc1a6eaf3aac136693954ea84830e9bfe033063fcf6a11ea4c332bd66805251c98421ada75e2fd0aaee94007a48ba4e618765589d1eeae7f7e251451c2946757235f395c354372c02d9bec3e020f5113e691efcff812f99aae11d6da4d97fcd0036adffc4b3dcb6620733de5751a8c0ac842f0a6544364ab57591a647d820b3933cc56e791336e9821284a3fd476c61bf59055f2f6302b3c0e4e3808597b08e96ef9e29e0b50c43d9c737d6552783084921f7ce526736fcbda20532d492fad01352e255095e31b7e024db36d4425706bba16d8afdb3229bcbfeae47c0de8ee070429d9545a18ad6afcb778b17fb0eced88034c1ed908248c66e0e739b3740338f6077f6b7972b3a9ba8efd72f9507524779bc4b1970ec89b53f98768feb0a187123ce08b50c55faed5014e71b977ba18c2a736b09152ac6d8dc57dc1ef913c7d6a1952cd031754902c56b67382c74fa99ebd383d76f301676cdecebeee2f8d194d1290c1fa2ec72108526effe806d7314d9316e4b62137b7cd82a3b1ae479ddd55aa68d665cb63152830a7ff26415da7bf74d7ff0f23af71aa101592e1fe4cc1a0c08d687b4539330bc783871211004fe2c3b3071742f66837e1f85e262e4766a7f9b469c99a1968835101880666ed9a56ec0cc2be8445ab5e7f51aafa917080207082a4ac2167f87ee99894e4327e5d30970e366b0346534cd7c4a7a301784b2075f3cf7d22683af5b264d5608550963a4a7f503546a34ca0e4ba35d5d72014e9c87b918a3fdae649b2011bceeb0123e3474e7939744d12afdc23aa77d767bc90b26df74aa9c4909eaa08fd91c32ad79f64eb1506965f4292d51dc3ac5a85ee8c0261c98e4711c1d91b63f6ed3d34282f07604acd2228699f3a1384fc0651ed7cec2808b7f3dbb76b29024a794f13be4ec1085a61517bfd06ff6f1183d65043f2a02b09062d3418b9013837dac269f4d468318305086ad8a23127205fd307f7620ac532c94605018c7d587d57f3620caae54ea57862833f9cb9dd445c0dc78da27bf553532a68cfc016c1fefa3e7e76277a15aa269be030815db96b52f4fe91601a43c8f19187d544fa5f61cb3b2000bc2d9f3d0987547830c078b0b6428143e181cd3706e9962c349d9e4ee77c7a99332217ba6d4a3a2f32c759f30420ff3e3df9ef1879e8de2182be875430ae73677d9ee1eee4df537ce609f50888d3be8f77615355ffd8b20b80f042aaccf18901eff24c115c42666a5cb078cdf70015baf09fe2db32cfeca1ef89496927b78e141de876f6277927bafde87573e58f03e31a62a6ff826d9965d2caafb8fcb1e824cabf7a1a7a0535192c2c2d4726425061867de35cf3a9a6a40420647eb8c27effa369de43e714152ecfc770f6aa87f3cbf57f5689512e8be0d5fd5e30b44babea240f0eeae7f224f11de6fc0eef7ebe7e707fde9d116e0a0c3028ea018330cddcf0d33955b2e9b17940630bf064a6a95bbf26ac8a981aacb6b1bd5fe087fa84a050d213346543efa426708b25bcd3f3b7f86e12b0c6584881015adb0a525f9940df67a6d9a35498150745295450da9c257885d8357bf96e95f11a1a64b4e5b1b4b7ebc40a2a2bf50588fdbc3a615c1c644dcbf2b6d6aa9e10f0fc77da99f7db0587df87401a93546917e2ab104d94abb959d1340f53c5671c6639a9db9f0dd887b6015d81c0acefd5c96cc434aaad50ea3b40b1921abe8ecea0a3065e62de01c0e2e37180d8ea29d7377855efc618551e4227c0d921fb4ac910748ce97c8db3cd84ebf44b4c862f78fa8d09874bab51c48cf6e1986dfb494e4aedd278c9bb461de665dbeb99d1e0d3deaa2e63961eac77ffb50be589513dc1f116fa95c9c4a801cc1ec90dcbfb20cd41cf3a1b0b378ec9206f11917e9ed56852ee3df0cb8a085ca8e8d3fa490f3b4b0f3d3b2d5a367353cf43546f9060e55cfe9b0f20d742144d4fb23b365c06103d9471e1cde981cccb7aa100bbe248a9097819c23b669be1e2bb24fc576b474c6adbbbd5cdedd15b6614ee5bedaeb6397b86ae763a628920029e6cf28d95a15cc35bdd2413b3e2987718b4cee9d04059722f2322d313682b75285c3bbc5ed970b8eb3c41415a66304ce5241f9004091b51608b21f692da28fc057c5162c9b973b6afebbfbc6c5e56cacdf8f1b8dd0907faf37f156f7c85df8d0cbbfb28b7746048e9760d44b09f52d5738f0e34d1b14841392d764de822459ed1dacc9c454bb0be6b17f68c9eeb92846a6f1b1a4b45f5fed674710990d8085b5b9446b527f4394489a068636749d9782f361aad78875de4ded86a0c2f2087d2751ea39f3171e6caa7987d755f72c3ab63c7f59417d727425dd7c1e825daeec27961d9168711e07264bbc004ae9b7b677318cf6119b155ef12acaa8ce67f443adabca6d5905cf80e172142de3e6fb3ca4e0dd74cdd3e504bfd4f3c0e67ad1b21b2d7307767d2160284f57aa4af2345fc606e269b6e6bc8b89208851d101a4126e23aa24de1b271ded6055707a1c347685d9b0b77f3ffdf533670c138a6c0db8b8f777839fd3df2a041e6a979e8203f7a552ee3f459b761378e0dde0b51207e2c14ca0390daa929242a94fdf220db2a7e8e1ac01a12c31741d0fe7c1bb12ef535fb12d41e85f3ac6167a9e088c03cb6b2dbdf1bf77eb9472ae3ddb536da36cb5bb0915f8dadb18d3fe6d1c673765aa18dd84463730fc57963b8fb66c8e4f86096d4bae3272e0322cc22e37262ef674b17da83bb2db1207a69b626195e965f240cecf0cf86cc6c3b572635b5a81dec988f897adee50d3df47881be49942ccd751c5a8e80d752a06d27d61a69dc6334215024c91e26a80e1c39b70742581a7e325d23a63092a3216c75ce0d43c378d6f15da651ab3172bb83c36696181d1ddfcb88eba93b2cadfae69389a77adb2c0d1a83b6377ed52b485b4ec5b20777de9301eb20cb628a7da80f41f52bab2437147506e8fa60907e36d96c1579e2bc1e506198d3a4ad4214701ee3b88bea9d34bc12dc365ee9c55d7bbf4beba6027e094a6d561114a297976adee690177e9c2bb2dc06e3e9e9c448913612c703b406f9a1ba1150cb23de64773ccac0b9b664664bf53803f32a0fde5500b6990c7c8738ef11e9cc096146f5ecbad665dedb52245d8b42fa0217ca75a332a5d69958376cb6dd91da81c0baec8ea486c85f016bb755d6ebd4e929b62d655b509c15f2dbfde2504babe2567fb4b3e627b6ce01ea122c8b163f364c414763fcbdbd74e7bbbb3816b52118e1b349c3aeac4662821c5b0acc04767a53a53065d9eef3ae44476fcdc0af1473dfd9de08ca99e2c9a7c92c7b7eece4bae6e3685093978f067d1398755bac2d93e76ee67c2e7cbf34721bbd6afe6cfaf8b51ce58f2edb02ab762cb1626ad6b5e79edaf16f1a9cfb5a020445817d063e200ffaae056f1d812e6e6d1e4039ea60c298f77c73382406d88ca6e6a52dcf102247242c51bde04a5cea622d6e41c5baa95a6ebfccc3c46995784d33353094a65d7407c6f73fe1dc2dcec6b31dae96cf5248152554d1d8b957c0ed283686368499351ded7cc17b838362b26d38d3b4b801e5fa2c439e5690d77c637a81819e9d5cf21ba8eb0a408b27b81163da0ab638f7617e996cdd8f80324907fd2b5ae6c76e877de19ffdd7d44ab27973c6a818dc551f5c77f88039c40746d44034f0e7e41acf43dfbe4b12916cc35538dea01e8cabdb1d3e31337112014856c8fd847647c9ea94c53e213d9984533bdbec7509ebb2924580d704c74861d36d6718278a6189f6f0158976de45ada5b67910b1b45d9b57bd8ac9fa5a8e3f35d82f47786f2e187bfe88d4935238550c14e2cb0cb52e84d0359afb7e0239a5e6e49b53190bd89317ee0fa9398f2f79ff50af71077045d8036289ea9386c4b58beb8c1b2d7634171af5fdeaf685cc4bda0fc355176ee47046fb6ee6ac861bb74a50bc0bd05b96f5aff85f8d06936fa573d76735d02de02523ee5b946e3e9dc4833677d6bbb11e7f429af6ce5d31e6ec9c06005493bf02389fd49a2ff24fc949234ce06ee11d0795df650cca9e8af25183c2754a8399574d93b0c91e3f5d2b80552d9c5f0d62bdfa72e6c0ddebd3d389c884c590c4b9a306f8ecf9fcd0807bbaae05b252f5793961126c6f5355857c5f314ec0d40559818eb2f4368dd0b76cdf04d83b2c335edc700c0da37d8edaab21e1b7f331d798f757db7cc9fcdc3234e1f6c0ac60769413f45ebb41ed079d3c32ce1711a63f0216cc038c24c2b524e8b5110423bb12dea57b91ea17ac0c2b05b41f3742ea939df572e9e3545b1296b722a968c560216caf4f54f2136803500e750cc40023366dab815d516f72251b9cee148ab7d27f8793f658aa4b524031c5a35a2c38935d36b296d0bacf22cf5596037dbf8aa9d49a432a93ac3926e90f04a6a0044b9ab71beb18b369c692922f2edefe3d443281b5585580263ac1615d6f6fc2c1a5359fda9a0ef76c7552f0bf0b0588908058977b8e77ede42603a108e09abebdddb3fcafa6863005fdd6c8ecd127c1251759e45884583943871485524cb6ced6968138d18bcec77fa3f6f602c5c645ade6473ccfa327836d176adee009f858868746670a8854e7633de0c5d2c4a4f86b9f464f88c902afcacafe8655c1ce57ad95f84bf28009113d3b5a2dd6538ccd13d700925056291cf6739a67d5d36ba489b73f1aa0d935f385bf2c63172a97658eaaf50cb1d2870153043255553aa4155da5be760979ffcd542eb800afe4374dceb347ef08451bd635fa8e523064d4c0b52daaca97dfea3865f39c489d01bcac625bb375684319b2e87e93e89fd63d621ea3fccbe1f915125d47c17c26ca4f36d95737fa9d0dd6759a8c6d353b495a03b8c61bff350f9a0a199481c19d47159d670e8f0a71505740db0c79507fbb9b7268a5b495c0c40cc55a12994a1b22fba0091cdf0a10b18f350f306c97e118e003e265b09159f435a580548b03b48d286e2d7c3c5746f0c4ed75d20db58762c5fbf0bc6a3575df5a8b86f35cb938eaecc4e5f23002ef1b8a8b2393255efc421f1beb9cb8652bca34053d26504859eec6abdf2ffa70b7dc39e7bf26c353542c9d14ca7ec031e166ca9cf5b66dcacb7747a489624d8711eaf0a51705cb863bdc1ea9091e951db5139fe2221c016aa69ec45d9a956db4f89aebacdcd858036d99b96f17554666a00d4887d96b5abaa894f5fde3ad3d9c3a5fe259ae9191f107419893508e9ee069020b578e2d79fc28019b7569b8fc21a857e11bbc561cc20689081b5bd0c0c94dbcaad6a8c3b672274d130e84e3b81cb846e3dd636ad0aa50af4d9c73db97db969b260db84298ae15b0468c3c245968412b915f117138f7422878f276d733da8cfa3446897b380b6e3b29099129363c4daa24c91875c6d923ae9fa270b63ba1222900266124108078a4360de07192b567b29e2ac7a45ccae18d35d663fe5e31af059ec91fa3a562a455408445cf2432de51bdf0214c26c985ffa708f838ec0793f5ed9a1731cf608eb575813519ede6024412719175ed68e0c6d8331e4819b6b74340330989379a5cbfe87246198aef66e624953d9f35b5b0e0ab6bd8d584a1634b885892afe4a4c631f5874aa791893e895da6ef5ef0a0cd1753da57565cb5b0c1d1625e6114fa235a313e8441f31be927e20faee5adc9b8de8a52bfe5e35f9642db55613c1f08c1d4becdce20909537e06e44dd569aae41fa30a2bfefd9bbb3e367713375081cef42e527568a17e664fe5d533da60e9b32121d1fccb225b70b52e26d73b5caa55a62c764e56f892c6c9facfb0953e3794e65682eafcb066685e38f4abb0dbe11eaa9ab9fe9fd5c0826e9a1de8a641a9d06bbd3fe485a8efe35d33ac778667615728c6e2c09c169a7fe4f41d1b8e9f6b7a84fed1374b3992419193a5dab7f48f3d069ae94bff4e934086d605bd7c085de4335dba31359d41d18c5db8abdc5d7954f431b93cee81f2608be881bfbbb68a78e5985fccb3662cf8c706a4d682a9acf408acb3b90d5bf397f96e1fbac6a0b90f6241ae3ab8422b3c7eb101d6b376a016c33c56e839ea446eea4df72881327dc4c61dc6bb2a86198ec3944d490d38cbe00b46035b5078cb836ea530258d23fc6a8d96149b19a260c6d7471ffc51f01a6ebdc9949ee4b082b18244744cad64d20aa6a9894dedda37ea6ba7058c96402a5bc7fafb49f0b022c040521272d7e8f3d99c154568d42db3f0c8de7ce9ec0b5a4d5e1ab7f9a3c285d6033c8bc2e064216a9c1805bdddbed75988db931effd474fe5afc78294b8d6a03056e958cbacf3431f57744351ee7faa0c7951a965656172e6ee2ca1504ffdc994bcdcde6b1ceec51c9569c9b2e722df65802122cb374438963e21f65edaab809891b7536253d6a9690608e5b44cce93189cf9765cdc0d13c6dc3690a2be49feedff38b822c9b7fbc3457501dcb8592875023fb75f5014df08fd85016d1d050a3d82f542166970b996d4b09010933488b0ef293193b736e6f684d212b7f63e55be6a52c5109b298315ee6960c57fb2f82471a1af5045e74bce5d7e39c88349946161fa2a3e2e87d1ad2c435721ce9efecd73ce785aeaa959b8e9c652426d374a55451318c72cc6a4f610424227c4465023913cf2b8c256e7e2585fbd53f64c7891de696e1ab5542a76a352c89e5059434be5fcc0e15c3d9393b4a4435e9844fcc59993568e1a25746ae2160f3568df8b9928cd3cb8fa2e11146845a994abe13a5dc4cfed5ae36bddba6179f21d5ee1cdb81c7db1b05bede0cbc0ffc03a97f0addcc2ed91099bb6520ecfac1a849f7ea5e780d9225b289ba1014964459b9c7b6466787e7fb4449e0266ef57bc6fa14c34056a8bcd7a16684cf18e1fb8dab0c1a769ea07cee1c437fcd9abd3d3f4ff017e30cb723096d39f6fb9019e544be6c0123309b9646d22428938c6d8310f3d8efd5b0e0161394fb78b7785b12a363a47f7a7c75febbd7bc68a8657fd9f8c3ed07cd8bb023f7d0c63f040fba41dc374af092f75cc61463e5fc3d59f446774a398b8e7811262d9849b22f33658826272d17f11662a3bf63b1158ceab26d0027589bbea36b5de2fb4ca51814961012b0ad471b533140f946ae515cb375c532925fa6b92d6079179540744db3f86723255dc2fa8bc79773543caa1724e92eecaa5d93f0597e506abcc585a2fac4df5d735e9f9cf17c55d30466f3f249739f1089e5770860757c85f2701b33fc779cdf7743134fa12a40bf53ca2309ff51d74848aa1e1931c5498f77961a8727f7d7cf57cc66d720c75d42f5698c3b0da5d17479709d97d615abfe7cc2606ed6bc90d6343cac4dc1a7ac8adc2f9e84b740ce2a80be88666701c8ea979fef93303e0c7dba3956d0b61bd1356f77f8ce8418841c16e3f98755e744e71218f7ad850777dcbf5c005cb45ec597d3d0d4254ec17d6fed55879c93d31b5f138d60ed041381d726419dc5f3c322c57a80b7720c2d0c68d547adc47bc639bbfc070393f2e883e16444c81c6a68bc38e79e1dde5c8dffffc16c8524643340ead9502953bb91122688218e1435ad208b73ca27c53b712351f05983f656908db724dba63f2028777f9a969654b23d52682688dc92d3a9efb94ebd3d23f2261aaf1933b462dab19be3e42731bd51609d97e4ae08b55e3dd6776bbfb031e109460cc4d8ecfba8e330349e95fc4384bcc269a12e4661118d374482c51e80992fc1ab3c9f13f5815685974f126f25c4046d3ea6b84d86687d250f9f33479ff3bd47acc02e742f49265d1a3a08e26904493c3522ed2e25492bb6f32c90939bc40a59487ebb939936358c8e998f7e7e0d0a7675d61530add8318ec2935457bb0691b72a81969ecb9f699f1253729629c1e3a0f626c0e24448495bf3450cc1488696b46fcfd948570c56e0e17c64208099aa2cbf2eee7bf3731ac7e77c4e760326272f5465185ec42e6b72a347308f858e5df7b773bce8671c3f943b3e0b26439816f3980b3820c113a69ed4fdbbbd667da259171f2314b757e4797bae8a4b4dc8429f714c4b030d7fb2f1b12b7c1170adb57805c96552a40bb15027df5684fd84f831dee861c5d626b66cf155ffc2edf249194fc0ad3a049069fa15c78e30417fa0919e796f99f0b128d70acaaa204f2e90899e2cf6ef42935124b1b62e776a0fba4ee2fea370b3fd359a32a8fe5fd360f20eeb5055e1b5d4b081797cb6b3ac79dba692e9bc979571c2246f103dddd96a2a20725e3e100522712152dacc0c3ae28ece178d09c67d6afe2eefb166e9502e79c138f6c9ecd9bc64b1d543315e79cdf04c5b4b928397ba673f86bc2970dc1248af830f61441f94ecd6627ee23a3aba95bf1f5dd54b34fdb549c177f10559374c5fcfdb2ab878c659ebe220c6146c7d3a44b46cf462e82a80785f1042f9eb950a1ae2b02026cfb1536a89d5e303d2b926fc83bfda37b994394ea3429fd1e87aea728df4ad0a84b0caf4085769aae5f206cb558faeffe0a61fddcf99eceff34ba4911bc508d3b7a2758a441334e58bde4531110c61cd05fa13cf60570afa061e73368589b32dcd50a8eed539412f70277e692066e9210e2f3d2fb864726db5ded52b15781857116d682e096660320b2da50290b1679f2638da135d8617a74e62c6ce66d0211dbeb4798435aca421a7dc78f6d573181e6f976004c2a448bdef16361375e4f195e0a6eeb03b50f603396f9c30d0688427320271b0873d0d75522a49f6da4a318739f58cee25f9bb78f5a8956a3274ad8861d766e806b3b8a9e4acb1e829ba982abf86be3349dfa74285e045c5d7142fb789cceca10cd35c8689f7e417be37922a055c31bcd8f4e290cb7f4e4016e7f167d07b0a53ba0f66cb870c48615a597eb52b0a5455833476b7d0371586ca75eb4f7a3a832035d885ffe3b40d1612d6dd7ac06bdd76527a00769531cdd371d2d5fbceb7e7d0fa03e175cb70e21ee7292e57896cf9f178a0289142f99db5e167b6e40408b98820ca92a5d1f0a0ea6f3d807457d18f290b9bc70eed7d8f16a89eb5ca349394ed99b2dd663d3ab3553416f1b5ffe539e260a4f8b4f894287d0dfbc4d060ebff31760d3355e66edf0e03f16e7b04e9a04d666545aaed21958b24d8c272f0338fbac3ee9e19be189b6c309d8ca1ad62ac85f2669154bedd9648112ce27067a0c27e52baeea2341aeffbbdce06711cde22ca3628a325c3783f30b7c97e98c98073440cbd508336f89373e0dc094ad000f5a6fb078960ad57510aa0335c2b3d53f36173dbf37c255c2601e28de39a95c8d6e3ab2bfe9cc0b7c5da2a5d7891d48df17f4520a1d41ddede174ec4a7974e75c0c8faecd14fbae4dda2ef2d517e7560d38e5c84e2732c24560619a3f2311f75e704302630b6dd5c5781821f9e42ca3a6eb3d38118c4bcf12addf7433ca2bb9dfb5092ca83150ffa5c2682380f7f95d34853f04f562f4eb4d3a020ceb4b444f9a23f752d6e11450215ad63c0a6a75eb60137aeaac5128cf3923932c07d1dc6c4b002e0f6c83e5a777275e08a31b453982b44477dcd094ecfebbb1730a25bef3f4edec2b07e9e3a2cb324fe54f0d33e41d6d52cd0114996749cba9421bd3f4daeab2284ef93877a947b872692007663c142d9844fcc0432aed1ab279a1a955d6720ed87e261dde368d8c95eb26fde07c9c1d034630428266ef63ab0a7f0de5fee12c1348e19b3be22348deba86fe55452a13ddbf465c572ab0081bffb3520bb1df622bcadcab797267931b7d4bc6d3812ee003089a1d484520e0a152d87f7975affe71cafd5fe461da5cb2013d841737ef60ec34310da6fd66679b67c66257adc4f6c528d35e0de60f4142d5e0102533471fd4c20c42ebcdb42275a4222b1dfecc3599e7e2e3d5c116327fabe9d96692a1d25e6d77bb2e3869eeb7b593ec403e20bbe18a12fd1a26f7156773d72c462013d81832f81ee29bd50fa4be7560ef1b5aefde3b0f55a65a60f97974d1a31d749dcb9d107e013922a09849b07d27c8ad1d2bee766c848fb5e73868dfe6e602fab9ae19c867271dbc843cfc20d364ec11c95caf596a1dd382703b7fcb96d5f0a80f585fe7d6ca79873e050c2193113cab55ea4e329f972f45c64278986a571a01cc1651c8a57ac371bff545ea4cc9ead9ccb88b3ed8409a409fcb79131cdf5b819da86c0302ac4968e3b3e14090b669d1849ea747cbaf24c97139365d2740559915550ed81d52431a7317d817ebf9f0bf85fd3e26f0f1412823306d0434126d3f5d9a9a212e035765add5a8f5fc5b66221404893650d7c73302d0da4936ed209c6f36803b350380dc205c7b17a5019a6a05ed9a023f517407526f42c6ae9b016b1b1df77beb0f14d43424d05e03be594852c62ab1912d7b1c61302930288bfe7a53a9104a98a810e592723e3840c86e68c00f267b16835294c08e42b75ceb6b853fa9111388b1315d8c7fa1e94476f0c2a815a591aaa87085174de45849edccaeabda1dfab5ebccfc7c81680c728f301b7c806d7a7b8b4babb0adb5b7b399595b71745837beace775a122cd71945bb03968234b48d18388c752a07839f3f399845ea52cd517ba74199b4361829c1cd5392e4a3455e43939a8de6463d4ecb807e7125a67ad47368879a2a4cdc25c43e81b0f153c55db0c223888a672ce7867dd3c001f978b7afbae39e0bcf5291707c40cfe050d1bb35a19822ea7fc5c3b118a5c7a7ce2ce1cd86cb57927647e5e25b8c9d64600a36b28dd52584013735a8da1d990fd23a467223d477483b1542e91d30c786bdeaa6cbf5b3b508547ca8632c197d519fe35f6acf2e3ea6dc9787f26996125fb0337d8d35f7be24ef5ac6e9074db90abb61d14846feae8984e6262aa0826341d829dacac00f9412f933ddb505a1c92324f29639ed17e396c918b12411a26d06632caa66edf1d590a4fb9ebcba2c5ff8f396e8a98711ffd3f9f9dc3a4c48acd3dee40a02d35d6ed7a9f0336ff6c58a1f106047662e0645a6aa525de7d65504591993024798911ba85f9282da0e330fe85fdaef3409e9d009a026f6622c2c4d0d8e100cc23487ded829f7f40e02d29bf566445233eb7b4231757cdb7a9e4bae9b331b5cbcdcbc8da9d076fb5f2c9b63fb0f0f865518c771c8f3a5ab33a4da06f975aed7a12cc434aa0cc2da84cfe0dfb30575a171b73a796a23424d3fe504d82849e53bf35f6eccf12f873485a8126bb284f5bd434af8de023fc88ae290b17568b73b981607030c7da5ef36c3f6a5dc20230b8f5d74c4eadc92cc9d58588d19cc754623a3b5f914bc7333bd7e078033e29c9c93fa0dba43cd70bb57fb694c5a78f2dc5c9c7e205d9243f402f25e1f5096ea1ba8e67615d8c084f8acb022e41d06d87dda0c12cbc005bc02f7b6c5e86b31832689e07be6826ae3b3f1421c9a1c033c223ec4b76dc6b58f8dcd1da484011b1d7a952f5208e3dc7684388c35dd711156e649ffc7af07f9c30bbc7b2a351868dbb697d66d5115afa32d65af83b7ef7feca5d9eadd6972dd1ec4aeaf1a8dd10c7c84c21190aae0d293c793c7e46380e93fef999a64bee99e515f08f8524b7ff99a9e801803bc341dd6384a922b681314589de24590d5931a4a2f21a1a81a5f92d35194f079ece64a610a009c65b5ad2ac4c538b35f50060bb4ac40a093910bc9aaa0012e918d988f694a8400497252e6c9d0822fb5f305b40b09e53689a4c7e7b0b7c52eeabdb5641c594042d78b725b56c088667c64c50e9db2b796db4baa9876a53508c73583adde51678168c2ff62c00dc903a8fc3f0273f88599b8ac54dda897749ba07b82236fed22b9eb619953c4179a871a6b5fa8916c5313ee6a5058accdc11f63b2d3a94255dc5fc6b384c373170d13ad1967b06a64da8ab25938a83a14827ece5e32e443d48da8415fdba77a6ad557ce4172e2f6ecd969d83e3ac6b0c63e46fae0723779d7f9d8dadb397587117a5a32817e21f2abfacbfdd3484b0828d1450b6905ac94d5b4b14177538e231776fc946d2a6b5c8024d8d5c8ec608e71f0910442c7f586cff0844f5d727000bf5f662c54409d95ef77f189b5ea3298c555c8fca1e9ca4853714cc990c3ee0ccdf6d39bdfb86718006187300826aea2b397f5803ee5c41e9c98873d713d9c5c09490be29dd44f32014a9ce84669161a26c08e61eed3509c05bbdf1b7ebb331ab8574517b3da5200ae04c157b6ccbb24949ec90bc3bf066bb58d87975b297ab0fb871da2126d01dae251173bf694a591b9230a1005da6f75c40c3d5480a8be26982708d6a98e3c9a62c1f839c7246d5222765eca6936a3964f1a8f8ed0e3ea12b33b0b8112a19ed222e2b719092f6d3231c54a37f8bd5edfe0a52c6a86fa3ae209a63c4a697becddda46735c7383bd2586275f9aded9846f952474f2b5e9d896863c143c4a7e7c6da9b18b153f13f3082158bb847c51bd5d80a68e2ac5751354291d770199a472d00f0f2f940cfa3c5bcf86d7217b57f009d42e720d2bc9d7d2f52603477e74dfe4d829b8becc28bd9b3e7b86506528127b0885e9643ffd1702010a7cc74232c8217cbfc565cb5f488716176e42e232ed22e8985cf62735cb044c152a51f936effc50ccf61852f796447fed5b08ebe2c0ca10be09473f84ce253497dd91626d902cca3fec0ecb351b4faed5c0f369cf698875aed1d4fe7b2a228b0fb963a0f62c1ea39b9b25bedb13973f296ffd53d5664a04c35371cc7bb3ce7ed1e0e519bc8cbb2cff778fbffedfc80912ac7c7a6629872986938db760849dedeb3b28cab0c936688aae8c3c0c74f59e3a6ab334927cf95eef4ced34cbc1b4c7de36ff830e30a0ccd63e69ae15160046664f3f0ed61aeb8bb908d70f9044114a6d8b5b04e0b2ebfecc5399e861e33cc0b24f2955b98f00a0074e9deb009abb34c629e7f2fd09d8f40c926cdaae167127bf71849653aaebb9c4f180b95c360c193e69f8cd9e9ff295a165a05bbc391f6e80321208bfbe0eeac6648eb7e63e126c2e51f8d5a5301687ba529b9ff5c5093a996d515e3ccf92bd8cb8201e60e6e2a4fe1463a4c097f765e28428d44edadfda3922289f601ef1127e4718a6a7d310a0ef66ff3cd699661a5aaf263d53803605620633a25a1aa2ad7fb2b75ae1bf1bb5d10822c85656e88fd090a08fa5fb0de108b3f39eeef473470c814f43439653e59d877e65b223702dadc1835a1c16ecf4b4954c87b19a40bd2e904cd317c0d7d9362e040f723d9a78cd856fb80b0068f2e82eea03d7a294e089e7ab874e0c4f01d0ce92922736a987751886a413ae39e319386f4c2ec13a14fb0c48dad4bd6e61b6a228ff73e0b990f54671ceda42072c408f484e1e2093ba99189f7b03454f65b51ee72571f9b156b24c322594fd8fa8093db5d04e50161f7bde91591b8d89732aa4fe3e3c8e6fc1292dd02db0ef3ee47dc723e0a6355ff73703ede7a0987250969a0e0723bf6799295408d0febba275f5c95650d13abe8f86e6bfb576d8defb086bb25a060360d2774f54f662cc0733c751a94c862b307e41703c239b387bdd68c707e724b7df5be9e405ae67491ec481fabf8d3c5f9ef68a5afb36a2e08bb41741b02864d4151b06855741968c421755fa8ee0199ae351a9b339f10ec8a15ed06c4e88f35183aabf78c6dbd7cb1135a9f4b0024fd2f0aadcbacc1b914dc0e9c504b08ac115f0e06b27ca44d91d4a7e8022b78c424aeb7d31dc38d2efd0387530be43cc0be4a34e002c110c83417755db35313b8ec74c9415b3087859cdd95ebc177773daba8ce27202883432651d59a252e6ec4cd920f69c3efaae2eaba5b7b5bd5b8974dcc69ddca1e87ad118e18293911534837af598ca0d0d71d7470d87d1196bc2e3437d7d54b2b424f56723b4f3014345f9a4bad76c27d14933bd3f5b48e27967589e39cd29d4d1da48c7cdc7f32e83bb8c44d472d674ca183aca98b44fe44dcd98129e1485d620e6fc191fb81a615ed87da36c6dce13c7b190932384c8b16d5b1225321c09fb9bb1d022b34e4a620364d27800afdaadf9aacee70c9ee927f39f1c10c1932e9db8b35030752e55bf1dea2a531bfde655e93ed34ed626ae1e3842efacbd94115ce3d1e1457ff5f37220cf811308d903d11aad840994c49a2003c2d7e2a41a58098e566acf7d53b1290c4fc52d8b87980f4fe55872b3ada47ce8b99441b88a3ea398c8d36f683e562ec7540a5f87f2d5acb007efb1090bf9fc028210b4a3fb3c9081f8029a1b6e3f58a6691fab194aa816d7f2e6e5d0bda7c2c935f6682708ed529ab7665a22ff0e4a03cea35e721ed0a4d84978dd0e5ac84eaab1b12773f004a6b43ba6a2f308f9ac5e5b6c787ac119c498cdb7600ed802c5bc187c9a5e66ff7371250ae0e1dc9bf9b80c49e8b36322e208a8933c171e03941e748e75cb61a91358ecf9ed69dc5544d38b25f6422efe8cbde62091743e7aaff90b953015b47548b3f724cb1c652edaa20cd60bf66d3406f2ca543ffdf2e27a6d1c937b3d6da19bbac5ccb3098677cb1d263b4679876baa6e516e00cba48eecce8943ade7c76beaba30941e2ba3186e688bb17b7bda36fca3368e59d40948984294576caa18e10631a64ce3bdc11a7d9582e20681270d5002fbd0988ed5c673d895d71f98d41d4f8172574b0c2747da8d35c1ebdb106dc19cf8330760d29844116051291391a68ac25cfdedf3feb9d1d2f677ccf5824186b4d0a7998b4f82b7da51ee20bc36939a3f6c6658c3a421d544ff80f3ca85f0fa067cd6ece10c14c416e367ef3bc27531c29c2a8cc27ffdc2118d6d3493a3a16301f45565e0c8026ec397dcbd3efbdbfd8b1c5c1e0fa9e2758f2b2a02de20e734d32d15791c158a4a118a3e826e6338a06e1c3a13ae572f45ce93dd655901200fe147ea8f95b8fbcaada08d3f78c100ac5810b4dd1292cb037e1c2c4a010f379a310147ef1d8f81de87d8537d8342ae313fa92d9f5a9310d6ec618999f45d8a1a41d4d76688261bd5e042b9893524e2d4f8b9363db3b5ec22d02f040de28a5bcbdc700e9c3d3f93be6f443ab950bc8d0a605dbb365bb3aeb8075cdde3392e974a90c0b61d66b05415a5897b5b2ced9c19467925d6a414e4f020de4546c764b032be07701fed4b298dad92eadb23cd65602293d913e132e36905c566d92ffe6897312dacbccc317116225941328691a7cc4544b593bcdc1b6f9d7aacb2645cd9904769ebaf63456674bee135b74ce863d5e88624deaa60bf414c79cab4ee565726f16216e07c585b3a49f71a816c256fc57f8bffe29d54ef235a02edb1355e05b6956714b8fa681c892f3e5c4af16948f8bb386ef1c0d08b3ac401a93777b1be527080a4c499fa79b31f005de15a3b2fe62ef0268ecd10496dc9184e8e791bf584469b49ea16ec428a577b27b7f1523368625f4c79cfeb064a4680213c382f87e27691e93a1d5bb2acec3ff5e31c9de57e605604225067e762273d237480c38d5f3c1f1995bd177650ff6aaeb176d2df00431935ad9a80c51357c7a88565f5542d366cbeb9cc88b2fd182efd5abce2b51a83e875d189d688a1604c4c61b6f187d487b5e77a0b3383f70d4111cbc0e512487648659228312108eb042eda84d121832ee4e539e7346b895068bf42722e232aa12164005e4d4d92cab1a40f68b03ae3a7bd38af155560cfabe9867f675769a29ddc429fe43783699aeb01f7d608fb9a8d78976d9dd5511f3648886819fcfb62aa7312a298a0af5692abad4897d323fd7be649de4ee3bcd66958ae7ded1d1746e2c1a7c92d7196bcc4d95d645c8774d7f6c9541f033f0de99fbd36d3b19744857acd2fdd9ae79a31bfcd599cdfbd63e2d746440399ced71174910676c4ca6e32bbbf1bb3cc03929cce5d4fc88b00959be589bb9412bf0983584db8cfe91553421a5a649924538a6e89f755041ea33e586942239134ef473927336e235648310666179429c4a3c89cf5d8dda10f8ae17a8b5d68609b86580feaea4aa4a30fbd263f5b6d5230413e4838207edabfbc8829d863ee1129517c5398ef74e601cc077771cd9b464ce8c44b1a94fab22409eb779076137041751f4a18b647acc7cf126da2eb7d286f354b912b40ddc3a740250c7e406245c7d506f02d48582cfda351b6bb9d6b45d5a06f625df0336df1ee98b754134ccee5cd45ab1ee73f3abd615fd988ec514d15ff1f9e66802157a83376e7e942de565c6cfce2b77a26975ba1ef8f62afc483bb913384acf274bb1f6cdd0afc7ae77c752b797f12b116e37c52506c93a8cba2dc55392807c5db39b33406606ffca327e5e305b01e190c7022595285bc214af2089965b0977e37bf61c6017ad9d585035b25be0fc07ccba24a7c97787f19c044a3c6e1e083f291498c4ad81535834a300931b5085dad0555c0db854c230f16470218da5749a5c6066daeea3437e37cd6c7f740965ba60b3419954c8a55e1937107fe1908bfbb66a00604575ccc2287c04b6707f72d828da1cae09f30ade567b9cf460a49d478fd57be33f1251e8c3f9df0bd16fae2222e8197712404e5a8eeac98f8d565a08de82e13fe13f8245cc731e3c93ef0d90f7d834d1701bc3c0e8e7656996204716844c86cc0413398bad785b111f1820036fd1ec57fcaee283af904e9192d7e6f4428f05cf32b0564d8f4aaa9ec5fad5e2df63715b547c3b02a5a44e0c1857c1435dfb1b0ea736ca1a00bec8e0f537b98ba59c4240f5f72bc1f30e77877e69c5a97d2a5d5c2c0efc6e4635d38a3e42a9bfa4f38ce2d77673158bb79fd0b09ee623276e8bbd28b734747b4650c4b6cc258d6f28a0f8b0d8eda9e15a4f3ae0a20882dc2c97708288a4b55280ad24df240c0dfd2e8b2a11ca47ab3580537a2c0764cee8e96513c6421af6ca3fec16633a0a3ced46c2c8908c373440ea480c7d4a39d9669f6ac93939c137403268beb8ba53ec58e52d263e638dfcb1817c656802e92a3161fbf598cf18126d4e8c1a4d74979743ab26cfa21f7051b5b2db44b3b586a8473bdd0463b030526e59fe52577e2c99ec77e1472036842b1e5fd62e3f537f04b69fcd530a6c75c05afa125bf11cebc32c72733337ff8909ed20f018b0bda79e2fc312bbc63a1a97e1aeff87f5b918f08753f0d8b2821b6319fa5cfa992b4e79ae6af6cdd9890702d561f2346b4b8e1ecb6eacc04d4f1c67173e05fd40212fc1461c15768357e0f11e857f3e16db2b3017e5ddf53bbeabaefdfc6f33d38f00747e6f4a6a5bb1f9ba5128523811d2f20915274a16c7ca3c768968ca04a1b9405b35f4d21f8d36779d4b0e7b7315d8adde86a623eff2d695825d63048eca68cb08a072e333e4a91276af9455929557c1d168cce6e3aeaf9e88c0aef0c1b348b6a692910933c12fb42eb34ddc742c0ac8a8ece756d40d5c6103bb9a787cb255cf9b066d2902453e85f7f85f489884da19134376e8acb34828c94d67453fde079d3923a3da9e1559f06b3212aa1c08763cec86b39ff63af9130b189a3217d0d694466b15840246e0111f0a9d917147983621759f8fd94d8326ab67eeb6ffbfaa53472d4314987ddabb9a8eac7ce81f0d46b6ca40ef704f6b0a0a9ba1f85d977cacd79c219f5f0a76b787cf4c1ab91671d49f4a919185375022398887c9e106c170f6f80dfcef3a98528c924e6188dd06f9c1d071fde6cfff82be3e3e56098e6c74f600ea7573cfe5feab9a6bfef70c6e87bde6cd7f8e8c374133b3cc01a4a6c8a1ab8a762c637f81127f25ee2cbe6f164e320950e90500ea6ffc86db53d6fbcf11afeaa8665a59c02ba202977fbff9bc46e288bcf622ab0cf5954d7f2909d654e582e6eec24ecf30ea3a4a2c4cb1a3b8f1f7c7cfacfe1329c1223995925864b834b204bf7e70aab520bbe79b0dbfff7a668bc1d5d00ea11c48afdb004c5a4c8a1626f2c321a65bf8dbbeb48e45e6e2ef48380df5386eb182e01ca140a7e5382bfe1ef9ad8784fd6c64da844e32b8bd7f090aceaa6bbee5e458c05da2895fd165db55d8f3419500f32a944c956caa79e8dd05cc77ece318d7c70fb54a06dc62085bf209d7426c537d84ba13f7333d7916be81199f9da6a662d842567b39679fe59d5fc53f8153cf46c397da5d4aa221c64b5768c848495b5ce86a4db6a8357d25435f6d56792f17c1cdd5baa54ff2f367b17050000a97f3eaf1edfc366a5cdd3ab1a450e555ad5d50b35adfb2697d429b4eb80130acfa2cb7447fa0111c5eb39223ce173f5992dede2418b689b6b022b346d44fe76cf44093198056ea38e4616752f0ba68196b5fd57457c2dcdeb3e0014c1d12e83bc1cf9042494ffdbd8f334b7e285e978ce691927c1b3eab053c8ad048a01329dea25a82068ee97b91b916c73f4be55fd0143032fa2b28b3351dacbe672030f8e574dff443e943130a6456e37f5c74080dca71d3c1321efcb299415f0017e1665b34f9c21d39b3afaab5b8f9410f43139f26b8d9e2dc24d8c66b8c3c3236c782df22be4cfcc4908e0dd03d0cd3de3862533d88617ab1645a678217de391384734f8a1e102065c92071722114b7f4f7ae11f1dc0b5b0fa3c773dbddba416540f1c43b5a77d45ab1183752ac4fabf9b8e4d0b8c792269b22b32c5a1d3da9a5430ad7787b1558b388806e43c37226f7852e3bc1a8cb73e75d13a71f853c7065c332a2e1793d6f554dca2f637fc98b76106e406ce4b548e0b2c4baf2095ec415a976f30fd48b1027dc419430d25848e756edb646c54921ffcda93d9b39d0738c984d2555e34a795dce73a6e6dcef614e408f4425da8a58f9804549fb2e22df994fccf15b67b88185c3ac06411bb6232b3ab3b94d072a136b88c676f0d11c7f7ac79399435a8e3be3dd2262b277c97bd8c5d4b15f6b0ea9b563e447e47b5a4f55fb94047d858fb36141dbacf2456d4c209f3955f26fb8b29551929494c7342ed1139f08ec9b7e60b39c8e1fcd71cafcd16d93a28a5026889e176fe9aedd514b275b1ba192e7008ef5314b518c325cb520ddcdb1b5f143bedca862fe3d15c27e6f6bfde55c838db3dc74d8c1099874c82ff5d38368226e5594f39faafb4a338f5783c6ebed21e9533d8ce3857ff9ef3c356b76cc521f88b97161c820593b5e3c04bdb030c27fab0e32592a1e020c249596c47a89a25acb46067389f491a6427106441cad4dd8872b5105d99037c0943813cf7413b5ec85e9d4b80db683cd6e484bf42a94d487506bf2c2fbc253a35e08d660aab599ce5d7ecca5e02c3081256481de3e1ce272545adde26a45608bd95406bd93e1f803e5257adedf9b67fc48cc6126e119679082fcbf9eb711fdf3440faadd6371fc8b798f479b2077ef5e9b761064ce8e89f22262e53fd6b0feced26abf6e79f71c65fc257bb5d0a440936478a0df261a293546cb81139fce487b6c78e710faaa17b500fd42399da978f8de9ef61b9ad5be1404760b9bade8ce41a0058d81c944bff8c27157a0adb876dd4a80e7bbc4131e99bfe9ffe8938f997ac9871b58ae2bc055df69c8ad1cc7c67d169331a6d9d18439474babecca37fcff3fe2be36d0c46baae70fd4b4fd756446c47f55373dbb58b2728ebba95317031d3d51fbf419185a73aae3a869aa622e932d582416f935fafb17610bd5ac6315a08a3551af8ad7b441ce97764dc2281a9556be864be208e50856eb3a96775a2cea45007226c3909d98a867b02dd5604cfbced57a3788fe5549846b68c95637c0b86b900c804ecfe6897083754f2c2fa5ed0b08f8be03a06a8da431e203e5de5b4353fbe1215d926c274ececa7fea37e591442d575e20b4884a30fdbca27d6d91abfd6c3ee9752153fc21e413847eefdb810e3b9ec158454c01348c0e7feedc8d8f1224dd4ea937ea5a2df2dd62a18bf3e6d249af8b4ff9a8604b6f1010a96eb3a946e7fce97bbc2d4dc9bfb6284e5ea6a8b6ddf04931db7469e3f3296d945a8d3fe3540b8e294500d6304c5403d0c562f55cdb2940ec92e80232cae28ff1280511aa16bfe195efeaced3d56cadd391e84aa6baf70a52118fab1163e4a9da745408e2e7c178d90301e4c6217e7d1e7091fb7c1ec562202c51eece68f3beca211d0f05809858dab4f05962feb3a0a9cff8b83b1570587357e06f9fe56f69d83d4eeb87567b3b768ab098184ab7fcba4792f2ea4c8aac80d299be844c188c41671ed506d78f870385e6601f3ba8e6f57bfc4a4b3587a57b40d767629bad97a79d247d18b1cab785fc26680500cf027b573591eb1c85b40916d783d0ed688be974fd25ed1b8d8d613d82a3453da43e687217312714e3334f889a78a8bc4cf3f30ca96039b05473fac7b431d6aa55fe3931d622904de221fd61e026db894f3cd44182dca58c5930ee911e74346a125fa89c490d15f81f98dd10749f0784aad3d0a8335c01b51588344aa4c1d827d9db2178a0e77d92b31ed2fc00da0823b95c3be0f79ae2fb282e4a1675037600069287c1eb22e228a3e2c21206b9b78dc0874878d40e3412adcf19d8ce5f4033a49dc43a09923586b98abf29b2a8b00e4289c779f4dcd79a72c3783bb8e539f010037ac6620ce3c82339b9574158f59a64743c1be6ba4a7f37e20c88bdac868973c7f48e92e3b9a3278afc978a481c72e2bec6a5efbd39e495a30335565c12e5b479146f52623aaea0192f56fc6b9cfef54b85110f9b238161cc31a0fd548d69ebf2c686131518844b75bd30adad917f2d3f78aa0933d674b923d5570aee14562ee3060095e6268d7d53cbd8e0208d9384311fd4965a33b6795e7e7e5d92d4662b2858c1686c9265826ae998f55b7024146275ad41ea27dfc722fa0a2c3632d1c987ba00746ff0eb05cdfb041f0299fd0a5a70e5b2da3c3a50fd198ff5ba01e6e5284ecddde4fac732d0962edb8c8760c28f032f8e782d592b7a4d8c7b42f5e7f36af24eb41920ced1d1ccb0e6e2fa1b83d08d50846ca097ed892e864a5bb92b0e53d49a64662a3c004ac6172cfa5e02d5ecfd095774a7b0a3e6f9d514c10add4f83686a2f34526e7f142c5b77f216c7ad5eb2a47718c4a2116ceff88bf233abe42a659ae62558dfa06233cf180fa4915c3ae5eb59f213ed5f4eb843e6df39f8c89cc70fbdaaddd85833bea3c6d32e6f985e1970542cab0fd6dce27dfa254b4645281dd7787f587fb937fee0d2b8d438a4952d5dff829045f256a62af8c56497453fc64ce6de49ce480fde7a5c345d71b439196b4c2088c7700b72006ce72930dbe5b012c99bbe58599bb627e87701454999fef8e3377e380cb8362db3731d883cf6fa1d118471dfed3557becaa34afc792cda79670cec69a9b1abd86ca951d3b36bc9ddda57bb067726267aa79b2afaf56a46d52cbc2ec5934d6301512d1c0274c6c98b74061e3dd269ca0c2c1746a7431a16145e44719d38ac6c0dbd659d36287db7e6a6a5669eac09de6e3918c922b14f2995f28915b04c29e6cddda13e7d1769c999560df0b49fa36f46d408adbf410f6f829ec470681465b492bbf9cd5ec08aee66bed2c0aa1d4fde3d3c3cd82978a5390977685fe143b64444d1d1415b2a32a11bb9a56e061cf272b1fa3b03adf76ba79c4a41c8ed50f592ef5c7247da63de6aec2f5dae2e28a09b17e7b093fbd609f4ee3a0fc7cd8154ecb1a7b30e05add93720b606a4c1fe874ad438d34ea3d05b0f626c4730a9d06cb66e39ac7a02216e2392558a6bb485fa1e748be2c6e3f23d1e617fcbc29d90a8b3ed749c697c3d80e88fe5172d8f9b5571f44a5534a474f0c6ac0ebc3e7d0c423f528d667d4ce772c107118bbecb60127fa23e7b800d673573ee6ff90a5a228d8a4e7beed943ed5eb2284309538d8acc68c30d72ee7afbdb232b68bcc66897c4ce04a4d42e7a5b9feb6baa8af115e755c5b2c0318b4f60098ee5abd7133e58b06051bc36ef55f42927e35e628a6e52623570ca44ac1f3a80e0cdefd140a399babd1ee4614ed53fe5faa8539df8ddcc6ced62c85d2f49e7bf5ce862bd14658f72de398634b407af1193211f98542617fc6082ecff7b71ab46765dc8997adc8310b84032a51928d1c9420c619b3bf6e8527d43982785a0e5a45632c9bba42ca33fe1a0ff69bb1ce4193f359c0f9baa897ef6f58b37a7d524e7cd8f40f8da9336292f6b632c07f681521694cdb584181532f0bfac5caab9029f7e0e4f876ca24acbe84948cb4c0417d8e21324c0bf04ccc360d55779a4ad9624061ddb8d183771ffe9e099088771be13d989a16a584dd692e3086322a387dfe31b283f5d58ba6b405cb4abd4f7166ddc77fc209909050a3d836a9eb1174bcb019180e8ac7ed093be0d1470c3f05e1730e1f3d90ebabbb5e5b9540c2728df6ff5ef996a2217b3b790fc0be90e91be32eb54cd7e9b25cfbadc9624843c1db665948049fedf99a65893b0fa88f7d8e04fa71ede0afd60907c64b80b4448f566f1c19dda912623b67cce4f121c4f5b3816350131d63fd5e798ac858327063a3364177cfeb29766251921fb8896da23655abde69243dca67da3aa7b627655cde6bf4557be03a12a7c32a278beab6241b0e220032b9c750648e923b8dd6a4ba8ee165420c416c2cc9e4b59e2e096beccfa052c51ccbf259b6bfdeaaf5e97f6578885ada50d162513b33c08d19bbfb80c9a3c33ffba6e38f92e6e9b7ad2516c3d49252b4789fcad9a563360ed0e0772c279533bd7743bea51e272ba0e18a6b8d42edba63e77ea19a39319ebc484f9a722653a36f9dad247ca9f190826ca4b24e1d136f8f8094c9baa6173b102d84099719da307193992aaa5e9bdec45399fb6e25088375427cbde9e023489590643d5df36ee99259a6be7ac7148140882a1597e63c126f4c469e2919ccf58cc371ee215aaa97ddaf0cf45f02c4818915cc948916fdd9b082b875c4c0158ef301c29a82fe07578dc4df3bfd81b8db5d4f11256df91ec2c5ea6d6b3bc9c12bdb2a25e9874e958c704b5ade70dc632cd0b246a49faaafebb8938680abcacc47eb5cf427a8152f8ea3d07a5e1657bfdcb7040514aee288d048fd9b795ad7f40d44914c8513ca94658e76bea9d0b1887b37fe9c5f3f7786146bc079662e50f729946e2dc55a546f6008d8114bbb1e2c709a105ed64791acf56e0993b004d8b156dbfed78d79d9f3091966dbd38230fd3ea3fab8b0d506000031916002842f8a04cba079e8e313a97c84ef007fc5d2ff112bdbd0c7deb31f1ee6a05d97927a8e5cab95e0e10691700b70b26a9ac3c483cb326f75006c008b39254baa1dc33f21d96c81fa353a61ff632ea1c928ce1f57c0a2bae62e797480419caaa6ca2cad16d350d7d6da372ade914d2ad1bbf6ae9f37d87eb067960149e61f849c26065f1d77a2ea818023cc80065809b4885808e60c9cb905fb45e7a46d6dc2b853e4e18c7585c686ad90018db5f41e709f60407e11541c7715cb10961e8581f4d962cc176d22bfb5a565dd6aa92b998b26365b49d958e60f1b511ab60b87a07f9a7887aff98efaaaddad5d0f439c9b1de2a01c85576fe99d245d09f25a79aa0fc5ffc5cf9a280ae6be08fc2300c2c401db0a5a57635a7b26cd4a4f976266bb8e6187e25d6b60d91165e8708e6f11e0b0029568cebca6eba6e864352304503cc1319e84ce2459e9f77cc2d6cf1c20099447f171d140a1e146267277569521fdc3a0537a998c9a6eaf0a9955a213588d0b2ca19442e55c4250874c394f45d41a57048b839397ca6fe3ef28d1fdf1d65f6dc6bb74efc104c9fe73140e01151dbe620e2a44687f661223e1463a74c17f03c589292333b08c6bd3da6582c0995188a50515742cfc6ef945f0b03bc4b6912ae970379356026c3dd938f66b01c319d7a256b7634adcca1acbe049c203cac82abd88648ad933e1611ebd4ba1be9c3fa1d550bdcfa8f17693a726f7932b289e771baed5280af4b545936c94fadaa7fcc8027986d4f3f11cadff5b4375c5d8837ab30f52de6268298f34bb7850db774f15a41c779327d6169b9cc443e1742bb1be6def15ea983ccd69df6e3bc7055a25e7a4691fd17cc9d67ad8bbd95640f9e413eb532a44bd1e3a389efc08eab919d6b7bc2c3f8b7d4f6ba4ad0bf7a3198d398bf62ce4bb5ce00870e43c72a39ca1182c107c5129843487cad65d44cd37aec979e4fead8e2a4ff9de0cc5121b6df16c013fd8df8668d336190bef48e3ad7928ee8a0a6a31d84bb3c9c8193a5a445ff9713610c5c2ed590f9ecc27f04ab9beabb614706c4a2182846dd4f579f085b2e79c74e7d40d7783f71c087b18570ae7756fa03892c049ba3b58b33c3a3533d7ce07b09a41a5ede8d5b2db0c3c527515d69c661ffe44f20cc679a524174f1d3ab20ac5692c53849580f28be72b046b15f41b3f174a3ba6c8418d084401439c18efbf7ae05766409efb19b60e5c3b110d9959b82ce7a1199edeba9a3c9fc2ccfecb8f119a1b7e4371adf98bf609479d477aaa8841a0f0d791374640f37e2bcd4e11badce6d4ee926aa1355f85b50e1cff9011e38008a997cebd989d3273f09e3f32860bed685cea6782c403d2f442f70b9338a31d2c88ca057cd4afb1952e21c7582ac7702b19501968a351e76de2306eca39a1c378e187832dc482bae65c22023fcca6c2344f70bec3e850e1d6e7e88a9f3da14709ce8c10d2062a75d0bbe748c9517131d60d69ff21d49e94b992738ae17bbd41353b8938cba2c18a14a8b939a7be26d9db661736dcc54e78fc9c102d61ea88ffdfaaa11045cdd93e7d7e15c6bf12ecc2f5a2059bc083f487c8e47cea791fe9008a9af2ae1ea96c5d23e4389931707d9e39ad65855042f495c06282d7b79b4be0f9052215b85213f4b1db952d51bc63b13f645c7ac4daae230a2561d813abcfd1e50bda5278b712e1e926cffb7e702a6ee6c3bbb0e1c3ffcc06d99880ced2c24d52100ab6f44810e171a00f4ec8edbcddea393e7377cec2d2929790067ec1eacca90825cf734e712bc4c1d24de22beb20f4ff55738748eb804cb2aa599cc21529887d30353569c653d373c6d9d7f62ea6e314df48e479f4b5beee2461ef8a3d27a6952e1f860209cd606b139e3911f472c893de5d4e93ad4ac29e9ea3eaaf3f1f0551196240e384269bcf79166792f30b24152ce0c2c629f7fd7569111893f444fea9b29a98d6fadf592ff02ca70d3050bd4888ceae28a69e51cba3f461d24d5591fbc8eec52f27c07343b1233df24854a1dbb57f0fbf9bb1116e81601739a3a399c15091435a332722bc66e2240109c4a61d50c067506c4e1784e85e005bc7bdf3a42e0eb4167961fc840f9431ebfae4eecb75eebd9a4a58f0a42648b683e129c1b464a0dd2a89b98b85fa20f5e29fcc94e78178a2df131b6eb40b21f13a5a271d9f89d55754c03dadd2c72b61ad85fad08dd02415bbd5e8a08223550721d1bf15c36601646bc9f5a6d7dc410476facda59ea51ac730f51965f5b76ad4e6a70184d22eea67b18af764ba5c02f6a1f8050955b5dd4ec8fa77bd9dbce33ad334ca722e4431128d2611a0497f11942652babc1a222edd1bc23b0c047d5c459ca48749e86a44a8938e6d69bcdf2a010b7ab196ee1a8325f9339f586e539be2cdc13f4d636bc769f692fa67539d30ba897758c48a425ea524a8783a4193090a748f7c46d4d353ed03c7a41df882a546a3222d56e8595ea31e9ce6a59f54a0ac84c297d192f37716d080578c15db77e4033be0812ffd8d8a104184a3b651e4490f41be8ac8adfd66d7a96b05557aad194fac6206b4511327129e9c659473e80f74a83386c6c5fbae087a4222c06e2e86d86c1c70d16cc19c3973a45eb9ea1a0dd8679b6a5516abee43a316cf1bd1d83176a86f86a2c5d02f777fe33122fe8774a811d2096f36a16355d98b230fd23e64bf802e3338de8fa2a264581a38f7edebbf06ea127bd7279132ec743cec90e16eb72da184b88324f60a09c2c7078452a8084fe50eccb288341c9cba9f99416b029de6ca42e4319bb61692ce564bf4cbe7b6f96b29538e3358d2a9180270951e0a9edd3464dc00eaeffbf75e26bd13a1d14073b2867c8a4d039b8567f5bd6f949f8689c0f28ebbe79176a848574d13f87ce0f805682161edeefdc1e3430d262acdda8e5bffb37fb61cad5d28055f90b1c8c7d8b18a786b0bec144fba35eabe15aa87808b9430afa327c943ab284cb41cf5d5778a1ddceb341659bf4641ebac749d8e2dd0aa5f41f1025a1dfc1e358d1c314c325bd97e5e54cd203086f9695d3485da7e20fd68f68fa961d9616893dd7f70e3f67633704c967e372379cefcd8d668923df76b4d5811f0fe9a8fc8f97c7f6bb948432bcef62deea6b7c44c887d6cd4d34e4f1a5d4651761e9628c012030ffe20a517559c2d06264cc3add89196143dde68c89e15cea343d744b49d1116886684c081a73c5815e9e2e984513e43383b3e730275554e89bbe5e1635ed95c5175623542f84de40606a00d4f6299ec5de75831f8fafe5618e4a341dca039ddaa23f0453561290ba5402eabac8dacea890cb2276a43fa0ec36b8dbafe6557e44abc030fd35d8313a62a94f0277e676ffdc1542875aaf154f2e32a5f011642256446c96fd1a338a1d077b4abad6ef69c643fc43108f37f4df7aaf21e2596f0e8861293776c02be7bf51168d95ea8629100c87d080146454026eaec60f2d958169434035a6d5e9f754d3df1edc9a4d5de5dc5a2a21474ee4afb36276e84f5a0368b06d51cd13e06d59b233d52169f04c7de4f09f0161897246f4196729c6abf29fdb222e65c54ffd7c4b57778609f8960a4c5d0e31d594bc8eb8244f98964b9fd53c9d9787b7cd73330210aaa35bddfe7a86134306449480f4fb5e4f717a3810f79ab95d84fe317fb07b7b4935df1908a2f45215d27ee1394e0cb3e0f771aac92016a34c7ee95baa51b8cf8ff0a695a38428a84c31cb7326054f5934c81e06947a815111a861269f2aa377669aa4fab8f1fbbc92dade71b7523797244b50b0650a3e776095e294648de64c71a44919b038078fa047e612b4c075e79f91c7dd0557fd6d67e0c67b17ded8e032d8bd09a50aaaa67034911c1ff3822c93793d6ddefecb4bd017baf4c555ec5245ef535e17629f99210f6e0638c25b5e9c02024bb01e0de244cac4c6226cae063790c5f8b1e52ec02701c1745e6178d60be48ad1a461630baa5aef8c251d19095ec0e7c4d9429525f2b55f04b7ae743d82cf290413c945cc7fe8dc25b36b6901b64f6b29f9ae7d96f5a5fdaff8a14dd70b86b521f7bdfc5f37afc9bc9f477531687c3a775de4d8df8b1ccb3c6e9d709fa04f8f2adcca5f947b58812e9626628fe9cc581af77e81ce12f940b1319bfb12a7bf76bceea48c8dfce7267488eced9d522ac73a6a4e207917dc7c5eb44cd6c5894a6f3e93ddf2d6afdb2c5c3e7cd8aa9570b6de10f29871ec03aa247d216451844cac8194eab8cee1804f1c89f5137ff027a4fcc6f510a5040d1662f277571fc07c3717de1171ff6dc84e4fc97c1ce1ab5907622c740a10ed1ee1f14567df187a03f8ce202e37fe4731e25ca804f52208bc1056bb5bacef71c84f23c03d796ec38193d58ed0dcbec77dd55a4b25cdeab4f97d57fdcdd3d0fb7c3136b6017800b9e6dfcd5bc5af5089badcbb2bacf28c7172bf6176004e31da48883e59488afb400b5df7c4067aacc15a2ea9ea1c6c42b20082599e4f427458c15421ca7403f6fc7d433f44b5d55d1771dcef2e0f58c0142966b034be479a2365845bdb3fa7ef2b7f2d023f1481bbf7690d4d5e3d127ab1667c9c3d61be59cb2a7e220cbf7efb332f4b70b6c4732779e5273462babfe423de784fcfcc6be2e22e94ca69fc834bfc10f5ed6f3418eb124aa40a8ffdc76ceab19490d4d57473d0f2b9c4c2584d456804df62e30901f3b3c84f207f654571105a70491b2683c5523aad310e635296b0d86a9d3575be6016354e3d80759645639add0c4a3ea8971ce3b430c2df78b726c37ea54fb5228392a9be449b4f42ebda6fd2fe90293bdf1ae831842df643626bf18eafa325e83f2567946a61f7a0260249880f8377d021611bbc5de3c9982c366ff763a9b6dc1bb23a2efee929f4fb8fd58c73e3d2f8537e14c5369d816819a31f1d87cc33e57076748746ce41731127aeb9dda743b867e0b2f48befc8faf6d69a9e7f4e01e73add1593aaf5bb7fc6e6291559a243f1a5cbf97086fdc45696fffc22cc5b1e157f0120681af31e063bc6f4869fb0ed336e4ad88c7950d4699e1e9c1c9b9ffb6996b43049da200a64c4cb5608388a195e4064b80523481ccc1b123d91e07548a331cc8181c3a9e562112dd9b82b6f34bd990917b480872abcb0e7924d0992e0c1d90295ab1aa95af0c90f150bde9dafea889af8bf265262896867f7d8830bac8c975404e97df7e7ae9051a9f4d0cc640c9d99ef9e7d3aedc85ce56cc206dc7fb59fbdf2026be9ba1f32a7e8e5d881b116677941045cf67790c0160fefcca5f416abc3f8c1441b4651ed5d88e13f3d0ac35e02971957945fd300792236fa02b1e33d82f4bab8faf554b4ea12d33551abde988b6b092c118dcd3c583b4821b3866f4533ec3fa649401361fdd4ae77833111a619af6b3b356c50978eef3f0970e598661702d28d33fd85784e77ed6c7e0d4ccfb35560362eddd39833d21ec4fbfbe970ffcee8aebadc21dc6496762fadd971f94aa95a08cc4847e63e49cdc320b5814607c6b42e3abc73a9332cc78738fdfec8c6ba72b44db6794300c85dcc3ec3c1068aed5f20836c811b889461826f25426906ea08287b59f9cb5b1e27dc3ffbebdddeb7854997f6a5961c0a65b607465df6f9d5807156ca9d61ba5d70bfb2ca6a37eeca751a9fb6e0bb9907e42feb380ff8798ad3c4c1d416300d8493bd45ddc56f38da674078fa4f438054ac31f3bd26bbb45ce016bdedeb2097a4317fcebe9fb2d4feda7fb70ec0d56160e0d937dd9ce948618b186a15b3544742eb3c5ea55216ed46f77ca7075f75517e0ab9c24e6080d1418769b49e3ea23d6437dee26ee2831b2cb28b0977e8be00108f288bfa9aad0606e0e9acd98ef079858e343b3d419dc6ebbad1384bc36b13a14905f291bb7b6f791779407f88d36e26fff378619ce1ee0799bb5d6f7cede37ec8c66e53cd612138bad996fae3da3dea74ecd9689ab023496e282eb52ac24b96996e273f6593704f6f0f11eb5f4550ace3e7e4d1671cc64597df43579ac14a6d85635266a0cc6eec43beb942cbb1bc0e689ea5796c92a9a13a541e5d1af97fc565bdfd0dd2540cf1756969e12028a8752c5fcd66d1dd10d751330dee8cf5d5b3d731c1b7ecd7ae1e3e7222cb78e91d6b8f75f1855213e5dcf3b747f709a1f3ae09545128f41968d0a076cc892490576b7a64f72f731a3b81b224bd081ec45e84d775948b783487229017a63ce5a0ae8e72c9bac0d652b4c37f8b17707fcdc40e8a7094cb123dec6cbd272c5b9342861c3eb2a367a504483612f335ba8f20bb5b84696512d18fcbb40e4119aa76706ea66f8dd21ba916e8c49da77770a651dcafc13c1fb4f92956b1f25b57692a75c8305a8c634f72b0696e879c30b67c62e5ed298e9406751266f46281a3b3dfe605f06af359d01af0e1b1765096dd0b379d69e8f11a5defc844a0e7395185432ed9d849a22601290019edd08e382d5849f4df202d21a6737e64d65117b95d79d80272a615120af3dd4648ff7e5f41f327158ec9e71081b76f4c322e076572cbeda22a0c0f2d20dbf2313e2b873a34b3449043c832f5841d8cdbc3fa09592b7f8a40d49f6af79af40c2aa94d4c43e6a36c5dab956e968b4950afa83656fc0e6a3a0cd0b0c941a8e6c52831a0a2f94b5138f99584bf8d2fc9aac2fd55ab28289a6cc572e230988a8bc5dc20f6bea9b6418070ad63c3616c4256bf7cae9701e76040dd9c15e1d53733d4f1400e2b19f9599a051278af1eaf746c6ef14b5a65a82c314b5f4be555b4351ff594ed43cf67fb7258429cbfe545a526c6b730db32660614400fdc49a08eaad62c16b57506d70c72230fa5b83a062c8ac45293eb6894b29bdc9069c196d87491962e226f27c5300adfe6a0a3ed23824f77612fc0773d49630e91eae0b97e709ae4d72ebdf48c6dfd93532a337c52ca78aa52095dcf7321977ef209125475ded5115a3fc312823035ff60edf84b481d98b1bd53e3693dab73f8191efa047e06f6a7850d5e57b38cfbb4f21c5fbcf3f03de0603b02faf22750655bfe5d8e4dba3b0b1bc0cf35b4bbbc20e339f962f431a05c8489df06aae050621b446b123b9bb56f2cfadb5f44a3b6fad7f6b5177c311119915bddfa3653f877b34e566e36d177033b506b9dff87d4437475e3a5b8f341b4a576062a3580ff85a4aff41af1fb3173e9be0f31ea38ec2ad2750cd3f69378bfe00597be31b96d7d69a86a45f9594458c4adfde6d949b773e57168a93ea54c90757cc9a05361fc3fd9845731726b6cdd24ce7e29787a5dbfe578b9b4778ce2e28927aee0d830c83d540ee25de8c9bc7cda7cac4b0a02c78e708188705650b4863c6fd944602d41c42b73572447a6b6f8c21511bf1c92f754dcc466b8e8804fe8bcb3d246ddc93aed800a81aea6dc67146924ba6201c3f6398c0d608b97bb6667a7d07e02352c887239a6bbc54c0c63ae5098d4ec412fef3339cfb761d429a1f20f0f9d3e62d52ed30b64638950a5f9d5fe2cbe622e83c891d5190460c0acf8e55dfd20429fed5a187a4ae25df6975929ecc0f15ed99a277fabbaf6f60e53f39f692a13c53dc022354883f2e1a140763cf271c1325f426a00dd62bdbcb34154f04805091758bf8e58717860348f3d16bd9f210a1a688212df0e54609105f411397a9e7cfe3b69d802f1adc19809710f14fe6709d78965e3b338a3d14925ebd27baff46500453d2e9111756bba32d013bde257f8d2d0d1df8a65b429a5c546e7b6d75ac03004a96915bf149f27fe3a685a7019184356291feace6c225ba605301f4c4db71f2b85047dd47a0fe5cc33ff496fdd530968b92ff716e783aeeea3bca7d39d0f2f8e726ae7de4fbd767f6f392b7a3f1fb628331fcb94f1e773ff2506454f1e20a4bf4054bf5ba56b1b42270a21768e0bc3f8bd4e9ec364772b5076534765ffb484c51e507be517f14b149c3e487d99afd080f2e7572f075789e3f1593ae24317d161fd1d42cf557b35ff06b35695aef9a1165ddbebb99a0f8a3a7949edf48beb4abb22338ca4bd0cad92532a6a90ce54c9db5449d4f3858faf62ead4f0fda1a05e9e0799c54f3038d2ea5199e8dde118067494aa87c22e11219b03df50132d2e6cf60f39a78e9c806a848a49575753f7cd8fe045154cb5197960e6807bd478aa7a9944fa4e19ef9e67ae5c8de23d6c2c0c65d2cc743e3cca8e286dd70be8bce8337eca7af3503c6116fd0586bf11318e27a5193f1ef446ccd816c44a29a8d68e4baa9cd39864360eaca75e74c9897e3470d7c610e15c86d754041ed33e7091410ab25e07a603925f5f69dbde7ce956f1ecaa222b6f8ec02b1c576a8974d9690453690a12e0d8bddf07ee8b90a08f7db6becc1f5201f98d6dd86007f7c609777cb9be8317ed9842b784cf166711aa71b7297cf0d841a3fa37c64eff04d7d09f13a4258013749866d92de72ce8a890d45961276ee4c951e43574acc4b56a3da6362aa7e52ec358119ce1c50ac05a5e717496d375e4480e6ca2dc39052eff96525ce7c0f89f407703f2d478eb89d9c39421188a700dbad8855c1f2770fc341b386267e82361be5266b1845e5157bf7402add3f14f5d866bc5f18dc35ac507675774856925c8b180b4ab8c8c296afe252b316d95b5bd6bfcd38b2b1152240282416db62dc2e32c66b6d6b09ff6138541d7e57804cda884e23c0db712e3285c7190ac22e048a892356fcde612ecaccfb9f7fc9e1698b2e5865594d836c839a82f8e17b10c0b4e8f07077023df8b6467328fa4cff2320984a96ed7862874666fa9d87f90f0138eeef12f88fa27d80337e5de2e5454c297ab5134db36f54db936a96600af396a22f32c3a3d54d1875c7d3585df658e3ab008d9d656b9085c8d410cf9ccff79e6a8e648f161f9885f085622e562ee399207a4a0dc2793e2596accbd81c3bfe1a6a430ba76d0044ac43e572ab7f4d4e873fb6b50900de2749692fa8bae60d97676b108fd03d8e43196754e4a38b3d58c951b1d0d2cf8a0e1eea88b976fbff3a9df664e990a76d6054e278890caba83cfd168f4eeb5faa78542c865b4dde2699504b53c2dfc9591f405b5250e67f9a5c4fef3bbd0454c9d1ede4f06591496be4123636d24f4d620179aaf6ca415106e88636447a94077204cd1fb64b7067415d7e31d969c0b443c5137c3ce339aed8a28147155e5f46d4a9b1563e318583eba5234c785e57523a91aaed2d0174eaea408a3506b2259d1b076e8654acd74ba75285914d93b26c675b6746d3c77b7acf2f6b5a9df3e9bb22936d6c990f9157be47d762f4f24c411172c5ac7af24312dbe0c602a99550a8dfda165b0df6d75bba526b009c31036e788fb43dd019dabc06b241bce4b22b3d8385837f0ac00d5c9ab86b9a5b32fbdafb6243aa68e07ec406e4980ba6d7dd01025502d8074f16a6f9c063f1b6c9fdcf86e9155c1cf8bfa1002f6568aad2409683476205dbdd9e12297dccb1693da4e569de11e87c4207cf4796347c8ba73bf7360ac55a1bd84decfa11aee43bdd6efd362b69a349cf52e42bfcc07eafd9f24963de3b7428859423ed9d690c748bef1d89e69e13c9475077f625e5082c1940e8397e91a2fa0de97c41c23821b575128e2e774d96a11944e808209147d9b6cf8903084c14105003dfda1bf2f8cfa1cd95f7d42cad3416ff2ac2eb395999a23f409ca032e9a59c0717172219e4b491cc7e691628914b045500d1c4bf97bdc35a6896c31a706dde311a5007b0aabb1f97ed397de56282667486628765ac0b8311a2ca43b7f16e6894612614e4ff57d5e643899d40819df88f1881603e3c70704fbc2da829d7cd1b9380ecc6cecc112fbd790be674be6e36f418bf4bc6231f24f0b40f2de40e84ff41c30aa0beda9765321bb0efcd146f78ef20b4222998c2fae2343615a06ed2e34e496b2fe9cea53023fac6830512f8f98a477e22a1dab34e139ffea47c0452398461175fd5eada2d584b9bed511886acb83dd43e576bb643775a1b00603d30f02e4b34259c733622010085b70621d12396740a46378fc2d71bcbd9047c37ef9c3125f3e0d1b0bb7d180d9a2b47709bea16731ff587fa544f4a90248e1ac900b91237336adc22784c270bd922b30ff4d32c1df6e801e63a223300824c8f7b0e9e78c378b597fc45dfcbac3f1feb421bda87674a45da437eb92d3d2a36899241112a1fc40465e0ae7f08f546821ce81aac39a1d50e2f09b116c86937607df039c0420633161a5609857b82fa09960e3e5982043aae8c14f8d1bf655615f8431b9200f71a31a94f7b258e7c24765e4af5908634e2e95248d91a0b878cb8132aba4aa438daa844271c1eb505724059b566e46a4ae1528aff48c05fdd97fbad6ff08ad5ea8d1337ac3b758792da6e0480e6c0c99f269ed64cef607b74320f372d58e2b3d1231c7b077f07fbf6ffec12d6ae18e0283520238928b81d582a3d399bddd4e5427591a5e04cf9128acc8e31cc90473b5d198bee0d7c44266ad985dc091644b2d9d67565192ceccc51445365aea68b6945a85a8d450cdcc6cc8d9432fd7a513d8a616be67f742e06eb5b50d082ff00945af9d6bc9810df03d553109938d02c9c64cc1780ff670eb251c0ee0204c2e277654daaa51b2991617b2da82755e3fcf1a40c09ecba76217d1dc3cd0f62c9467fb3b5058a1db19bb5e0c08ff6363de1b04508eb6a715c991018f92076a9835520a6281631febd0d13e5158234ab1195eda4cbcc347358625be3cff2b4dd9149e70234427418c0389ad65e8de05c8f34bef28d06fd82a40ab9b2974fc5e99e595dfe9ac6cf5ffbb5b645d3d269f288a79363eda3595a2b33181face95cf4dbd1a671a350a9048472776f0e7f151d58fd81879f0a01f27d092676cb9f3f0dec3ef8923570c388785eb3e08b05ab19d6ab58bd8ed1c225bbcaf38853ee364bcbf6a8146b19594145058c16841f27f8da935231a2c4088f6e7ce2bf7881ea90787ece6dbd7d0a70e2121e5af6521e6c5861c088d9f9bc80c861a5e9239f7a9a799859c1ce0bbfc785cef630740df37694123f9ee036cb5be49d30219c4984a3056c0bc82d6133368cf3dd98c58751d3669e0519e1c7ae8c3476cee9008285e557f05fef7ecf673b53b80c1ff6f9889b3868203effeb14b1f2a601d2423ae5511c2ba72072deb646a66672c1f57fd0c883a57cfe7766022a6572d54d22f74daca65c81dc16729925620e7cea42e18e5fa5b8e948528843162813c882c352bea420117bbcfa9002104334c843bcdff46d638b4b08763edb3c74e4c1854c789fda487bbe01a17e90e3be750234ccda532204ae046c2161214ab0d1ee34303a9f8bc2b5503b2dd2199eb56ad46635c8cfaf5b09c69bdeb0f68fbdb83b8e683518549506878d554a19d713eec044d7dfbba95c0193ad6d21ca369f069193af0556cf0ddddfb71953d45f240efaa9819a6b0c753b3ec41f0d261c86fccc92554855b4400704e85e7fc2addc1b812302690bef5d515d99283d5809389e3019c76ab75e2f7ec51ac4a988437f68f04ae4fbd267f794c65e955639092796fce3b086c14fdccbfa08ba51e2d906e5c0050e73b2031b849957155c29d856323ed1d205a47997d40fa6b9ee3c6bfd89b8d18dd38b72955ea9e78448edd3bb2b8d690fd1714943c10f03b7d15df0f4d6d4c095137dad94f4005cf74d698543eb347e6d3e27d55f1bbe89f95a71a182faf66b6be7fc719e29efefcd8417a3254e1b997fb9dadc7ec691db0aced4d779f0d4cca1de5a0d7e703e13f4b16b66daa3fe6fc7bc7d6c713c5922cf1e3d0bb5da4a8aeb7f0af47e28045e78461715d0ea75c02cd57b8c090f8fecaf9b3517068f224f52cb708f8a21a7f94be5b304b04d5cf392ca850e2938742168beb0e55db216594f5ed03728f6bd9720efb1bbc66f4c52597ab1de8a11c34615255f9bc17913bc5bf5238f0967e5d7484a94d1385ac8d3e7a0cc00e5431e1094ef2160af71788d7fc69d81c83e4dd46e64db746451f5826c48d7050adea19ed89650ed0fe31a44b233d78904cbe3c37a1560298252d9ed2c5e38a37b25dc9f3a2638a6bdc50ed7fbe5814b26afe83332350f3d0519bcd3c0581c5a772dd6719cd5b05215a5ec2e2b4d416e6e360d4c7c94014a76f85696eb454d831657b9f7ae15145686f1e9f6c86ea43abfa6de4556fa12d45bacb81dcfe4f8d211442e881466270abab99dfee435ac7b766e0efb4b724e23ba4f374c491fac160a23403337af4d753de9c81b909a9f68df48e17ace8c1a588ad17c5836794e56604afc2a5b5cdee8c3e13a36f866155ea4b7ccc84ab4366cf46e0d75f47514835a5ad234c4ab83e81bb82bd71ee60f29d6dc24eac304988dfa6376ee04e08d6b85b4d6826fbe69db2e2f7386772a7e37cac35cdc997daf9f5462b2b09096bd3c3bbadf46afa0e629279ae3865d3302f26b9a716a51878df639d4ef0085a2957861f87d7fc35162612572c83bed357fe04bc99098568b3413d23f090526d4d28d9f17fa070bbebddb691b20327180a172b49e2ca79622825e47c66701863fd039e131a4634bf002ebd8d728cd7c482c5b2934f44ce41320f2e9111f0e245f617556650e5ef60680e023634376ae78646166e578d3e55a1f49719d441497849c8e44d5e89bd822866e35d158133aa4f4dc1ce2d654e09092c24db76432ca3fee29b92b4d20b7ffb92705d18a465c557131a3c5f3b18724a2c89f7b0717de14b7ee95cd261bc4fb728a9dbc23bc8d3737550859cd3557edb3b175bbbe9727d0abd002355f63bd9be9dc7f510523113d5b5046973e26ba8fed91f5f070023418d194e2bf48f70409f6e40509c62330ac1bf7c73eb2461e8c375916f56ea375af0a80e7715f5ed3d1ff85aa1a80f1dcb953c0ceefa6a8ac18e960830ad53096cdb5996d17455eb77a7a8f02f562acbac73a633485cb175c02545850ce106095f5083d7389d9cf1741cb3c00abd5a09325d8b128af9e0ab60009145cd0fcff6ec9be3f66092931d372079cf6253dd0ca4dbd6a5dc234f16fa424bb3270d8f0a985b540edd363d3d4e1017ff0c382908d43befb2eac7bdb53bc5f640704974a8baa263f0c49e5a08e15baa51cfabd01d9e364c94dd50c77c5a6421ae14f934e0f349a71f0773bc3b99206f1466432b79c3055c7cbbbf2389350e9687f0ffa52dde1ba87c1d994908d921569dd2596057dc4941cc158ab86ae24586b28427ee5c9b8a1196d4a3c8122db8375b5d37eef26a26591049b8df590c0655e91373e390e4f93ee579d953811f1e9de1e4d5d80e9c7722d09720a5279ee4005eebc1cd1f2b8563235bdabaae0a83fdd027f98cb971bdcce891e6247b2f90e6950edee517495dab0d3d265f8aa5ded2df87c77786f57052243bb6a10a863fbb1164d3464d9104839e303284a46504b85444233b37b2d7edaad895dc3fee435d7c9414a4110cfc34578deeb5a471569d4f280a93ef36621ef46ec5a3732484e99e3f49b224f28ab7f30774f399a80268468141ce5ad8cda4ce4e9b7babfcdebfd2dd6301b3856989ceb9e231a6522e2354fecd97a1d4fef1cf300489de1e4cd64e50c15c20bfb4be705af79189c289a08bf720e1cc910e994895bbc2977fc21a7d92f210233e7ce999e1e6a9bd91dac6ae2333c0dceff2a62232a117cc1ce682038900c139dcd19ac86e27a94d1ee523a3c4afd6b2198be62dbefb4c4ad522a30bb6b3612fa4e5bf4a962221d61707b2f063845ac44f8e35e44f3e36fa636492329c8149fa1363b340b55ec5dca1164d411b0b20337f0538a5e19968a24d33c78558949a462ba4f3bd76da360164901eb79dba0a4be9a04fe1bb65916e6348678529e129b9c7cbcf695edefdac0f6e09c4b8c124277c0cf6381f7b945473d75648b025cf4dd8efc2527d715a0fcd5439702472d1a8c6abbd03e3d08268133feebad312247acfce0848a372fa7a6c17fe344a5b61b849edd2792e96f452cccd055044feaaf4c66a20c2132637bcf64be61a573bdf6fcb5091e1696fbc7c88800ad22198866fabdf55cd9b0f067f651818331ccdf06c85ba328c0b303e337281090f913de03da5a6659be718eaa9231a2341b362dc5f0f9a9cc64c310616adf6cdd4ca2a23638d8306b2488acf18bec08553d27352ee982843008de695ff5df98a6c79a5b1c501d6f0add0158c22f22248b5a6632cabb024841372b1200df746985dc3d435635f6da5dafaf6fc44714ce6963c873587694fe7c0967d5c80c91bae3b892e97f0159ab080c07a147c0678b159b76b0ba4dcdfd11a34be5740a47383896f48383b0a8fdce8e765aec60133c9b061b6c5ecad0f21cfe16be8690fb20f49f8b4be8a6c25ba7870838938c401249720471b5070df45319d180f56058dad5dc63165ccbae8c4115098cae302292358d522142620794a87c4ef595d0bad68912266471263ddfc19e726ff669b88dc4e2bde381fc7666b80a0a4b68083226c870dbeae713c6364c21ca6b2b57e1af3e76f06e62e5125d4f4c0748952b03163e6a4f565e04dd646554145b4f625ba63ca91ca9c7ea255d3039a23c96ffb2f31e1cfd31fdf535ad4bdc6cc3e973590f226be7e3466f39a035c9a9550bbac647267682d8c6200b82043d62ffae3724dc642c3ed227b2bdbeca73ad8b3543f0617b398d06dbc0587c9728c4331864ed84f9a9ea1a34a1c8c2fd161c3fac9a8ebd81925139b9be3970f0583bb13d3ee3d2d24e8f6b4d8b0f5e5989f9a2206298c3d0d5f8d23612ae290f21a75ab0bf4e74d694c67697e1847d4c1d7a26f715f8f6676242ac3b94242d2a82164e9e465d6714fd5b82eb47b5646e22f7a2142415952dcc4a05bb23641008ebef6cfaccee383879c6d3d8d57ce399f84735788f398dfd1d0deb3ab3b4b8dfa9fc8ed2533609053baec7b936ae27356ebd1962a8a7eabc67b8cd089320eaaaa49674a507a483dc5509d3422739541149166d8bcec00a4d5c1ca3f6fcf4925725dc0307cb8b5841a19e455bf54bb062001ac3a7909daa50a6d3ebf7dfcf15607d68ec5562e0d7b29101f16356ef20048563489f5e288cf8242604919c232454203046f663fe8d087988c47fd013c714d4c7a5eeee10023add8acbf6694cfec6085e2c11eaf2fea36ad2b349a428898e6814996de9511cc14a9b5ddfb14eaa60c1079ae2ca94f2d7c39cd0a2475e037476c7bc0ae82381e3a168b4370b3a4cc2c5a00670a0091ab9a2aaf42d4c02c9d0bca21e9cf73a5ea52127cfb13a2ed4f1afce5f3c67f28524b4f74005f8a295890060975cf1baec59b24896e017eae3c40a165eefa8ad580285227559fa62e5021d71dd08bcbdad13f65ccb8ef85556e5ae8c715d6159c6b5b7903d1b721d13a3707fb995240708dfefc1d44286f119636176011b35e08222ee2dc6caa104d81a6cf9a736402178a7f997b9b052226902b4a3aaee6878ba8bc3b22984db6174963c729cdb0c25ff99faccdbe1552cc11592c600df3dea968f29f6420ce772e25906d5d3613e47f6b492d60c1cd34f280a511aea1cec2f5150ce765ffe9a686c0d38906da4e84989497bbc0fc995805a060e0ab8862da526eecaee5004d6510ecf0cbcf06ceca976f5fdefeed6b3ace0519d9cf19ca95bab306deee57ff8e3f88189585970cc65acd56d18fd38dff5f2709a8afd450d0a5e9a0a99872103b8dc7c6265a6d9762803b65ce86b648d6d3e23e9d831323e3ef25cfe95c8a6d3f643c8dfe44f6c188be6091dea2e3806f88b2239e81ebda4a753206bbcbeffa1334eedb0731c095bc71c1597f678d7f0abcca7c0d0d4f9ed745bb761cb6abb7efe35d36b390c5eeb11bfbfd35eca6b6a652a7f2a2a27d2734c32f66b7272d80e43642a2a254feafe33f4497f5ab673d2ab38b1318016b6f06cacfd3f36886b15b73256f702006cf44c3b7e8c88bb01ab09fcd05da2282c5915e76402e1d31ab34b1c5c312db4d49d1ba81aaaf598a843c468c3d0dd991c82680e3ed8234c21fb47bbef0ddc23b197cf21f608a56711aa3a1ea6a305b5a77486b0a40c31201c5da22b1e05195c3edf2ef6fcec61208e3e81df58155c951f33df4fc9caad6b972ddfd1d3a008d15607c74363e3a58db80469751ee818693b045dc7db84cdff8efc7b101d4f41ccf536b8345c3ce066d521174aa857e92d377d8282578896a47a1b25e7c5980b57957b51bbc9afb306e260e5f34d34cd3e7003c9b6e8f13abfd643e136afc4d1b6fb8152bdfe1f5549ef9850d048f9a7821be53130ffdfe60dd652c19ee6cde2d172b9fe007e44fefc601c38279f7996c96f3e61b9f60c3ff1a8514bfe98648bec1c898bf78526a70592de57951d99c938d1dfcefa06b6edbcffed5a221885ce44d9df6067810525322fd0ea4ae2466a1b2f6a4b3ac7b5ddbcafbe41a103a2d72f288668474b9075abbb201ecfb359e359804fe36895cb7d69bdbae8fb76ff607d5fbeffca93bcb22c3168072f6d482a3059188309f06f6cf977d071e1da4ddebebcd06fecdb33151f0d2e0088a0c538a187c01b25d7ee4ceac121b1a34edf089eddc7c2dbe97ca1d9e150470d7caa7666e00870b7abdd9fad144fbd419b5e41845e0f9db69b09b85ef15dd186be1a821c4ffdcc8125c8b6d3001d53dc946dd2887143742b7e830b94e22639dd1cde7d65304d6eee6867d117b064be4a3290e6562424b64f8d4bb2ac530e345193c27f12ccffd2ee7f7892a89ba7d6da02785dcb1e1b58ec9fd69e63c1519a99cfc85c97b2f157c340b47cf66c11b1d2c8fe42e8f08b40e7c4231af2991b3389a5f77038095a25f279b1c562769d85a766f787730435bef1c747a0dd0d9488299a9ca12199bf67ea541f693b5855932d1415bcf091d08d83ad65462e41b0ed74c4ca07df59cdb408061c8e0e345375824620cfffc9894f79da00e193282a1b321495aef52b03ffcb72a5923bcf3ceaee1ae25868c6564b6bf8359fc657f72b189301fc581e71d48f09cfdb71ab7e5f3e092a463970855e16764c883daa375c0f4f0c4da35a94644ac950574036f91c00ad2a29d826a824a5199d994dce0a2ad0f16159aa5a9f3dab23315204e8113cefb690b3defadd793e0ba974e8eec64090a957b219233c37086ec8127ba163aabe094f3acd498c0c84a9f32770952d36459e219cd39057bc66bef5806a0da5bf8603a6f7d46160e639f9105585e3a349ddede8d4ad5844108c3a1ba545698584a9a6e66afeb6cb1253dea5d542b4fda3b532b77b01251fd7e678185ee78777aa23bf3c840e3ea62a534e9999ad643f6a96abf21f45b77237d7fef36161c8600e63f8472dcf301217cf928b16f170e093a6a162c4ad3586d1764c9f4f426071ebdfb68846c22a6d26802afab391d7e5592ec3aa78b50b220abbb9c468ea4695904f68a77aab2327b9f3f61b1cd60b4baa47bf746dd6b128aaa399e32fa60a1939870d13d15e05951a63bf30859033bc3e2c935f93bfd56da7a7550922a98758dd201c6e476a576b82057c5fd6bf4916959004b94d7b0fd7c03ebaf9439763d44056fc32632519ea31f9e786fb210e4a2c172390fce29a33293b67120f397e24766dbfb38d6f79d4d6b5f9106652c007308bdcd220560ffeea4d08213d3734d789158fa739dcdab3ed2e621865f5bd8cb788b5f2154ad7143798f3c87b306834a91adc613cff331fbd4577255550ec20a19b68c29bc06d4d1b4caa0991b8687a453a1a0331f6f17fda99a936e0a96feeb213ffa694b545004732a6eba504f504aecf82212f4251c0fef081b744512ad4591cd106b47c1be0b8e8116ba2a8412c8f14514a0b2267e88a194937ed1f32e243c28c24da78a6f2a8f5e53f20acdec75145135f5be1b67a34577848448356c1a5a5652f7d14e71fd40302bfcc40d36716f473fd2b8ad4b75afc2d445508ca986fcb53df4233991dcb6c32523003af88e2b5d1c9f9f2b9a325f8e6d000db4f3d891c052f4df014b8ed3541296ffa14f2272812434138735429b8d37cd9423028315b352a5b6002df949b06b67f575f29a234856c36b29f45c53930687f7b168c47948d980bb199e53d72e0c568c43f84cc0b6e179444c1bd848bbf0ee02dcc6f88e7e4a73032516280cd2b72891638a8807b0f4ef1b75d7c07b0e95f81593be76433c941c631fe9ea3ff8f64a3ca43b9a744a2441e258e1696001a0ceabe1d0cb54de3b6359432fd67c0e9dbd5cfa656b9dbe6478138418ef238453d975f4cd6ffe19def2ef99bdd7dfb210c09e1baa5d8313e41006fe35f0e0224225459436a36beb204f671c6cdf50e038c3107ae8db8f90810af83f74e0a4bc407b2769c804acf5126aefd2d26363a6f02cae12a35dcc185f1619f1644ebac3f75ddebe3080628c5e94eef301f64ff76d94c72c373424a0b9ad4efffb5219940fae6c2f2c86e7e854da584da1962cb1a35a0cb3eb4ee3487d11ff7409a7d0878e6f96cc12550f9d9d398e1faaadbfdd503cd6cfe118fe3f5ad96617439771926dfb508730f55ed8a7e581501ba40c7a979f7f98a7edd1d2fca73b3d2f8f0fa389703eb48fc35feec02ce535fc6c8e9b8b2196a9936f7eea021c66c3a83fb67f2f459709bdbae99a30ac6f22eacb077c8714994fb14a099208939156bafbefafb740fbffe92ee18ffee283301e80d86b9f806fb2a8c7794197acc4dc73ea3f58f2dc299d00443b7ab3ceca9df7af055d50c641468f1a439f87a85ff2e5e59120a3dd3877a7a26f7d70c6fe299e2da2f150ade09e197c10b35f498465312c4c6c562962ba92f5f57f64147e64bb8120bb1fb340d1386f9ee514df6497a1bed8c5ed9739ca8b117573e2e1b6c9123de714efaa52f60d406f080c57770cb2dc4a264b3a5c6d34f5854e9dc27871b35dfb8ea2eb554aad046cfec29223b3b5dc9544439cfe2713d784d83d82e57be68c6d2c80e21921408ba90bcf8814bf36ea3eee519fb41b0e9cd1e4fbf87affc7dbcfe6cd8f5d9dfc3623b9964cd96a7c782570fc87d4cd281d133d3e02cdc13b3bdfa11397b62f1ef91c7b3d89ba9571c15ae0099dff3c0131ce35aaa9cd05961c3eb6b986f58ad8e2d1c4085a5c3a5612baaa95a57378878e8898bfca18927e1688e4a9f0c8d9d085973627917b0113a02bbe43ce001249f00892f2f1d1554d4db14670fe99d6199b6a4432dddb7ffa2b20aace0e8eb33d0c3b1d365698e86ac32239b9b1361bcf07233c60320a5569902fb0598f0b0b6f88dd1fa977caf7317c3d33e5db9624ab1a15bbd117ede4a3b77ccaed8ed44982ca878bb1fd5f2a4a9d612801551aad22957fd33d96d7cc47f7592350b996b8fccdf6bc927300ec9d84e2ed8e212a8f34e340d555b6b64c62ade31af476099c9890c0cacf8c489bc0106e4c351e83f5ca70dcf2e03c4d014d654139ac0667a4f74aa29270d14eac99475faa859c057c4a0948726acf3d08bd708ae3ff44be66b7377265edd3e03b59635c8cb9e46ccaf4e8149e849cfb1ed79b68400b9d8234a4dfc8250ff0ffaf44455cdcdfe57868c76707ea881f5687e8e60d4331ac02a369774f99792117fdee28ae30a2fa0fca5616523cc0cd8dfc6379be58835e082ac2244bf732bb2dedd97c202d944e7b41cc09936a0076305bc20bd654adfa1b9442ee52804f8694964a738e88e9a38dd56584499289ccb2644baf4790d76f4cf67a332bdb05922624fd2c74b03e7183a1e86e556004793cb46b23d8e9a76f31db83798bdcfc427bc2e35b24ebe0b4d9af20b5224dbefd51899a16442769adbee6796b6330496667f7bc0759e40d1399229be7e0648dd426b8698d8de2db65d15f7f7d263af8196bea7e51c1f3c76d52d6354ebb0bd59404b1759932968960e5","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"8a01c5d3519b99bb5af51a466587a22b"};

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
