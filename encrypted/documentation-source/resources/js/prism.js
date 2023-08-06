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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"6ac7b1e78f8ed634b7dfa51f9205e175b177ee357a1a992bf2498fd752ff5dcc0d5946c7802a47bde228467446648e92759f1ba85caac297731db30b477dddfd24d2a26269f30b2192cfa5ad36c0056f491a5a594b070e3daadccd9537304bf8ef72669fcffde79cbda787c8200fd996ad86df12c9018765c0bb23c16e921bcd1f9b9e1bde71d47ade93b924486c2e47f889a499af447ec3a892d2dce523f82d2350aad97e5ea4b18d1e61b4f2026051d07b1bfe69beefadb5445a8a20b54fe03aabb11aecb1447222bd67aca56d871204e434f193df23f2d2dd2b9eb0de6a384105bba53b64e1b6d7a4d651b71b852726172c71ddf42d3a6e69b6ceede07e995ea3ba04a6d1ac493e1116c3baa1c39498fb10b8487f54660ebbd103af491c8ae3336a52573afb925a1e7adf4ebf9c2ef2c2f9c4a0fd2900f8d0107b3605bdb202c958ef08c8277ea95e57c0322dcc89cc989e84069d3798feeec2b242d850f2319228225f771c2922de77ab80281c3ec518e90ed879469fd2f49275f2354a2ea27d85cc253ef67d9723df22472b86eec97dcb38fbf41675ef5eeecc00b2625cd93ba2f181aa82be2b2659369b8d6eb3a7779c2718125a9ce9de0aaed7356225ae39b557d15761179968e9a8f6744ab432072c7d080cd2c3b9b4f3e1d3f1981fca37a771881c21b95e662206a32e9deff3b1c7c0bef4056de363dfa57b27953c92f844cd654cd9fffa99588dff1eaa5e60672aaa93147c7c728947262603cc01492d7aaf56ae21c45b53bc0728461b03466f24b94fc96406d5d6f29e81174877a57055d54d4665a44540634bf632739add83a5dd7e1af6c8bc28efb8924a8d8d3ea5f45abd92f49b28a3a6d9f8db97a206f6b7a56c6e53a3468148c7e58a03f511b6acecab0d55c4077c9b344b259eb93a1bc9af8c67a0b97d8654501f20a3bb05f836fcf294ceefcc55e4680e55d60871c4b215d5eb09fb923bc69d9960a8d62c8a5543a3f03d936a9004afd35041eb102a40b0e2a6f9042d6798a325deadcfa195ad50238d75acaac9a0c2adbd3c653d8f23a828ec8e90bfd0834cfb066bc3f1f3a4b745f85b821f51e496ba343072e44dedcbc20c9bfce4d9de30e1423d9254150947002a931aca9a559f77ea3647f8bc4383c472949b48021703e0682e465271da0790843e9e6c846ef3bdeb8ebf5bbdafb38fb49e02597b6cf0c10469bd88961eed35f2554a938d8e070836fcb862ec9aeda7fd214c7cbea6c25a34a345fb7e3a662a0ae5bd7dd2ff64ce7a6c65398fa127dd2068693fa2415be264e8273b07efa02c75f0889f082583dd89178487b5a335ab3b6e9ed929d2050fe4fd945e28b8c91cb44b5e04a4b01da8cf1c291a7f0c38e960c48db04283b18cfa26dce41ee3a06fc3b8edab12f0350d0d553c66b710d265a3310a0ef31323e67adcb1ee0e9fc95122c6adfe4f72c7b2b7fdeb5a48b282d30684ccc560469dc3bbb20f951120c2f6d8d71203db4906350507fd1e6708d10e01e8a1ab54f161f1e856a9a58dcf3547d3e4bd7b4051633744722b371b3dc9aac9275da21a9c53865ece5a6e932c2b2afca12acf2b254e221d64ea36b455eeaf26d3af2b85615e686d961126d44180211465f040c6d4fc08e099ab668ee3d304c2c331cef7fb3bc8c6f59686299b7c58ec279dee67e9e1a50086ba9c0fe4f2d8bd1e760a73161735a260c1bd5d50ce28905e8899278d42174636769750921abd26bde965d81888d91ec3891152da8103c88e72a2d815411d47d7f8d968350631b4dd1e51bad3e8f4cc15d76cef0dfbf749adf91b76e386ce79b2d88f48580648828099698158a4b96f3e31418e9e62b5e6a66460ead93734515475b8260c304f55fd0bdb9651f11da00957002a7064cf7a4ee4202255649c1ba04c151f15748b0f68692ce3fe9c15510204d43ad7ae11210d1ca564fd2a9c8c0756236e0d7d3c9b14088e1ac776b1bf587cd8a20fa4ce28a23811bed441e8741b568b057fd673bd46fc0c8f35f5a5ac265c38308f2f4a527652a776937a2b0155ebc433beb9254b11a971316f6e8f85d62718bc327adf400ac07bef2d9c196b13f368378b4d96ce054f48d460602caaea38b632bcaa254b4a20c9d170de6a655918331386fbae919b300e8ed52229cafad7bb5dd51a653993f8baafad88c5412326df7b5944e7db06dcb0680758a9303db6f005eae196a8584a6f46f83affae3156d86e0570bd1d46a33809560f973a8a19c681ead0416082af0bf613f4fa474f2123506c592bab39359af8fe51f7f8e6c0d90a48f11e5ef195feddd00e40b96dcb0a6a428cefdce83441cd4e724ad16dbfc3883a464a680b879073c5acb723707a86c465a3d18e497d01547340a20b9d0030a28fa5a86bcf4e74140b52edf5d22ba14e148f2e5ab8cd1b648e115b89b78271ebc8e2cf2cb4568a4567fa296a4a3251e6285b385204a97163356b6431aa37d33bc6f3bbfd36660b4c64eaace404a8eba7fda55f172b741c4da487a8b6696f981b9429f641a971673e77e5876cd3c7adc809e94d719f505599410885b812c7b0b9fba891d366f9fb2d18c964e7d4e9272198b4eea22eee698b0c8f4678f80d3e07abf22e410abfeedb7a9c801dce03b9852f83794b40d5e8e151f817dd58038d9344eb6040782a738e0643b2137309c9c1a544d23470a267e6391546c47406ee16d30eb37db9af03b4232cb45d3d33170865a70e6e120914a782094b88d649437e23ba547753f4be9483cea0743f7a4b79a94177ea27b1c42facd8103d6f9a55d1c32531799d5c83b2c743e813e922539435f9cb971dc09c63c673dc42f9fac31e5c614b1742628bf25d55b381892fda81a0dcceda6127186d0ba57567ead4183de29e35c95438523c2e39450a7e136caa5f17fa114542f16fb0aaef29cf0b72ecde499620a3c9caa761c740041eb20342efc044271d0afe14c13061c541800112d331036865e293c8e37dc9bbd19a2ad3743f4714c0e122e22f570f8cc1fcf5b40e6f5fa4fa61046e8489b998e93839bfee5b75cb9929a3fe8e24087b2f757ec8552b44c4f4b89ec5b0550b495b3aadc41bab28c39366054835dcca916e5a619cd891e08c6eae2291916b783540a3617c1057feef2a089b3d0063b6417c152a62771f40ed82ec4ad4c1b867d967f45bc9212f9626667cdb695d621b9792ddd773260dba6617be8ee52ad31a5e6d10796fd915d634e3e7b1cc435a6d10eee43d803a35375f8b70c5341ecd3f7a2e0a127b7d3967e64c4ae1976d4de4eda075b095d7cb381b4602fb86235d674c3fbf3c4d890e869ca91e5ce4804756c8f26a35e25bb91f463d93f7587fdbfcf4b9e26149d94219532a0a9735f05d0304e222206576cc6a5cf8202670d32c550ede881cd83c7d6954fa699a12dd4c5021701a74e93a16ed76971ad20119a88e9c992bfdfb56574b2dcb028037916a8438f01506e6e48359ae2bd1aeb45163f6f36e168fef3d7b387428d4970f67ea44593e30abbb6914b7a2a04fbf84a99dc4e908bb06741acd6a05a6c3f87338b1ad6cf461cbf4a268391c512fe4dffeaa61c581717aae6111e9e3b5d5217b318a86a7bd5b53a2508665bc523996e09a690ed3107249b1576b22ce3b6ba6944f13ce749d78dfee993359ace49c75b9b8361581cd449d985e7c1b4eb88587daa0b6a8fda0333996f2c79d24a088fe22585707798a7c049cb553bb4f52d43e1530a7352f7729038e6ebb08f3450f8f86a0cc9d5069b81eaf80fe69a3cbd5f95c4c9a6272c839ee3611c8786dbe08fd2891a554eeab986d6c0503c1731caff743ccc455aa91fec0b64853bad09c2dc320a1baa73641e16c31e78b10b99fc36633abc8c6d51b4bf89b28cc94bfd14153571814a4026bdc82520969c3e7528b32c62f7b68307bc2542525e2e4a59d2719702f4f9aaae391abda125ae8f411614ed356579c8dda9cba55b4cfa6112c71fa3261de86176de87379342d134324c12b0bc642c6209eb6be78f62b9a82112d9653f6666249fd96f7c0dedd084022652d129abb3c323015ea1ec9b8753d69ff9bfc7d64d12dc376f4ece4dd22f665e9510143e4cbe45775a1a279832568573018dfc9c10b9f005dee9290532f67a5f9fcdc4b7ac4f9d300ad52ff33238ea7a1c8bca26e01831cf2ff43fec47cdbf7840d5e73eef240017ce61371b9837718667bd21841c7c67c628790108bfc48e4ebb196890c46955024cc038f38c25750a9dd5eb9f881c4fbaa9fb25463bcf00543e947ab4c7a8d6553a88cb6c67de204883cb2216bde466cdd22ba895852f61111317a94fdbbe2786aea25a419492804d6b7f276f1f73b79a7ca54193333792aff0ac685d12866303aa0e2fa724dd2c4bb4856af7cfb32f5bf025952a32f64f7395aa02e9546bed935e360ed29340005a5890f6ea3bf358110636a31083f482f794eb01c3e622694ed036bed19a8a80124810fddeaf7e706eb053cd6c6600ec03ed5a789b1f107a8110d98c1c162d406f9d146942390576f8317d7eb153284523fef94411290bee79c054c366723aac7131d0659ab872dd29d1544d1775ff22d1790aae08fc06f9f329f77a0e8ab9b486905bd68841be0745abba93534487528aeb2e058ce787eae5cfe5ec84d4f63dabb68476cc53a489263d1a8b42761deaf29fb039c623f918f69751398125573ba6ede99096802371260a58d0ba4736f0aa24dd48138f62e5f8ae9961075e839bbf02826cf612cb61d3b15986c1610c103a2d715f5cf6b31c5214ba35e25d07f4ff8b977d1e0bec2b7fbf3bdf57b9c174355032804a44a9b23446f9ce9efa742733c09156a5a5972edd872163a592432a50dee43f43b5202125bf5613f1b96ddd20a251b28e6d2eef26c1051a4230509ed51f43368217933a6244f2281a2f414dbfc86afb97e1f27bb7078c3d61edc8a7059c6d223185dafa025fe4acfc58835bf5d2e187bc61c514efc8f1cc153aed82db8311a51f9fc3276929ad547c4c6039d27901a91b896cf766fbc51b9aa35c65665913a5d52732585180d476004c059f3bd993ff61b5f114e96e7cced35c4a6ed0041e743833123e3b16a5794f08cc7cbfb5845762919e9eb1aa93996dcca443cfb754cb13edc2492c039b10452ba5b1f1164d9e82b1e43f27b9d0afb02f353f7f08af6b0ea6e85cfda2f65769b6357e99470e0e6f3d8a4562378bb023831c0064df0c983fe0e0127135838f66e8015c72f67ec8839b45b0eea1a49d396231769184385128ee75a0ca30eb39dec2a15da5b5ecb9fc6090e0c33ec406aaeb1c72f440698839b6caf7d78be24fb5f1aac4b7ce106e753939a428253a9d4adb5df4ab44db86fcd22a36f50c64b623221399e52716fab763d6c4c33b305b5cb782ba74d246d919fd7ba8008d9b8ded798017c47f2afd42610e5fbb0ead6f08a34daf40e3754f272e13c0fed724cc6c0e4e5fe7e210f05a9d4a83a07903fff27d32346edefe596f2abf3925680c9decbf1187eb30617aedbc45530a53aefeba2edd70533f94c2b8ce7304ebdd4bb66b812bbf1ca99b64e412556e3ff83713aeef949e5e328100fbb73e1bd349ce557121743f4bc7afa0bc431515910b945145f04da26da10d197e8b6d39f9cdf92bb12900d800ca1890a625d525ac40388a81d304a23bc81ca06237cf355a27596ba69178aaac8c9148c11a18e685a7589286bf854a005cad14a614085ebd00609c1964d3c802947c14740c329a5bc0e8827300fc85c3742f2d79fd4156f078ff1f9378a764d783f106855c04177e6563c73f202824291aa50d6dfa81f57e8f669afdd12af9c11d6f4c3637a1513c0f87f5b8ca6205515bc1a44aadc65bcfdef13e820eb636d6689b7c13c8607a938d85f0ee0912e140a2f2bb843dc78e96caa3d6c4d76554fabaa4b4de44c67f0137d4be3a2f42e94da9b04ccacb93c8c19c8307b8122f2d0a27cd547b5c87ff8af1edf272229d3bf48b32e8499a79fe8bc0904a104aa7d2ba2ea32d503a01bdc1ea9abc99932480930968cfa601e9af15313b6d785375f71c1b4a8eaf6f342340f360ff408959ac6d72795043633932a6daae8cc1b75c74abd55044f53db41ccba47f4e8207a506c5fef57b5bde17f434d4d9d6dd63ddbebbab5ee9d4ad2c02580c599f0ae86a603eb34347d452315b32a4bc3aad871e0db8ee0f00fe361e2594bf823c49d6e15418e957518a414ff6354d03b756bdc0a985d05225d0b00b24a587d890ad903d9b3e1f5d0d8043d7c9640f08ea8d7eece160e39d50af4f8cf6f293a0a55ef09733134fb778ba678a553345dd9747a36fd693565b29e434be7581b003ab4821c6fb0cd9b4e7a43007e10a91c20bf23856536dd9ab7bdd57875f9077ab165a7ebd4826afa98439fef1710130bdb3e39400f6f8ebcb19a15a6c35ed24a0a76b546c4ad9e0c9adb8507a4987defd7c9f836ce0f0cb6ee568928bf76386dc8325f7b7c0926f4f7a7ccf317c50d576ea5a92b603bda0a75c06c0ba04f2014cd36c3f2944c50d0f5966b2875fa71942d974cc01da07e888f6d466e60af624714db805f6af1d1a3d50f327f137ab774abf4f6b1682b34f6e0b0ef2016029f6342e76bf1257c3c6de7aa6794fbb54662e24c31afdc2ccd245f8dc3f7fa9cdf8456ab0605c7aa3e44c69eef18d8ba1fbbbac901da7d7948afe44bf173bf5a2d6134099576cab1d8e0c07cdb4980580a0d537b7af3d4a6e649c9a23e51cb6157d4d1640b06639744b764e98a5d91b49ae337870b458315f2891570a645f6c4cfb5c49bbe1b1f18a0022e4acbcf6bb8c27a1249d92cddd8edc3e6366327e2286964f0f9822755b397d8316dc410a1c2584ed04475e854fb6d64e6217118aa3b4bd38485a8c498d46f27009279c28c878f55f8f6f7f9018d5be413e18115bf5b7169780e99076b3d49ff850fb5707d3cb5852765aab0b2bea6437332c967a7913fe28941b9d5b7f8520a63156f85d33c06f5e0c10edb8a90897287194dee57b51cb8bec03bc10e318373f188e1d68090e6dc8f661dfca128db6acd6b8175a960826188947c8f023a5bd946ad8a0e5592076334409702ac6c67b3f56980ed8dda55ec2fa9177a6ba0ff7620eab60b967794a8ecfcc11dca3b2b20dec7c55ccb73316be757b834dc11d36cdf67d86d2002ca93311b9492bc7af70d2591acc2aa09eea86279a27dac90315d9456c09e760ce63aafdaae0508773e4d02d47a68814d34732385685576a00a199de10de10ef66e579f53724ef90fe2dc088fe76ecff95fa6b012972d3e375221b9cc7feb001d3fc45e30e1698a3ebe064299780fa152e129f7c223000ca5b7331d25858c9d5ca0fc975ef63f9c4824254758fcada3d7a8b9d427da6936d9f07cdf9f5c60324d8a5eca80844d7b630de6f60d59e7c776bebbd868232c3399cffa759b58b2cc43d9d16be61d82ecc830091c77898d356eea87cd2e91d70cf690015dac1edc517d23dbb85e5b94b5ff09be181515a9d261cd509ea98fd7383e7221cd4a3d9ababf562f0bf0b66e72f9d9cb586d0d3f7ebe2728ae51a4cfe5f2093ec2f522f1f13885358521d68a6255aaf622f5a8991dd298455664fa81ea55fe31d0c8394055188d594c291b7d958e5110e3b396df865efe84160d875af811461ddb8ec5d2aa3ec5f7045ffa77da4b3c01013af46e1b1ec858d1ed915cf123a1010aeabddcd63f7fe3b3a9a1f68c396074eb3dad5d9be4ea3bc11e018ed3fedb321a46395d5c90cd4189e90bae12366a7ff6b87f283e31d464806f30f5cdad77fe1d7a62c62b9f64ebc261f35a50a106b14425f2512c0e14f6ca8a1a964f8d3d05a17df0c040dd47771ba70d4c15cf276d9db8dae45a479b05fad3b969aa700b5b3c1330208b9ae2f89a34ddfcac2a32fb85fe611642a9b7340a659541c95fabffc78f3df7ce6770502577919fb33ebef52c74e546bb38bd0bc41acf7e4796999494abad5ad6a4c1e3b0d74ea8525d7c41e4aeba33cd8586194909f6bf659c4c99f6d8384f1dc8c89409a291c1d8f686a296a4eaf6619c5d47f65aaa25b02d29fc9c5ee12738e8a4c3fda914c443688d2d3def91500bed5ef1b68a54bf78e4921fd4ac067829bff2394deae99ed2661ca4b347e6d3384975025d9756725c6b89c21f2c6e77e5ee30ce5ff29c3928af6b560128868e6fedbe9981e8d42b4952c0c5c1353b678ff640616939b644024dcacf913e1ce1ff537804c92e9af78c140c3a058fa64acf31eceb4a115cfb024c416673e7dea23940a299a6304c2b0327942b170003cbada10d138ac9ba4d9e8a427948a001a5579f8415019cc7b1ae4b16776560073c0a33c5e7cbf4427a35a78300a76c7e4721fbd21cb549355d4e2f825a80f86c1cde1b1c53e07dff89e7e2192b88e8433c7befa08a6552142feae4e796f213ae1aaae93e3aed4a2e869f9803e7dd6bab02286815a4fa1995c2bf7a7f47cc984d41de6aed75a8c9ce4cdf0316cbba9da65db12a49b61dda8cbb9747fef4c5132074249032661da7a021c9069bebb40696960057cb9574f2c8a99364ac39820d20783a24b7b84e9aba95629323b54eb451498fc0b464d8fa8e73130c7d570a89d1fa630d04afb51b4f68fc410ebe24b03fc66dc35232776e4e9499e983d6d17bed80bf35d5e59822f7b15cb4112e8367355fc4ad4bac60c10a328f9f4bea826f54caf4373a44262b7bd8fad6e5832703a63ed79a356d77f7755dcf964747603449846b97244a333a2659222ad03dcecd2c8436debb31e944c2c3c2311b2d082880dcef05d38badb140ab417026595c88e5060349658757d9b6e642927d6a4343b41ebce87495612243d478082ce25a457a25c2fdd930aab5e5df346971444e1c84ea925f3c4667385525114eee3289cfa5ae052c2613d3002976dac5b3db8611043a94f4c41f4dc1b9e4f1609f831c05b17da553d374830c0714704de4f471b5ff25af44f4be6ac29d514446209bf020f2b8242ae0a6ccde524803492662f0cd92d387b62195ecbc4e2479cc26f25ae44a69dc2e27976ea18fc2e47613f3c8b4ae3615e51597f14ce5cc0e805e7fb799320a6354ca5fb5670b795351ae821b0fab14ce9a5061aea61fe0d38bc6b0a40c27020a59459f4bea131bf557c0cf25d3a8064761aa4b8a77ef83d9a9af5a588d96c792a522fdbfa6276cc593b1519a06fbf38de4049e120261ec5d1c9f66429ac7e3cc4a08bcd443852e4a92fa380309583f20e07957a726b90a5728c2362e53b1b39058e7e7328cc5a32c5301c61e38f05d441d24504c557f93c7905ed1ef0ac98e5751021edf368d39270250745f022e92a8c73ec11edd3dfee182b5843ce24ce5473d33568ce371895c9ebe3e20668759d0b3ecdf34a4c2bd73b29a158ed4a6b2be1a66d99a727be3a159c2da0f4cb9e2c29f65eda976993834021b3e7ae405c7ad933e4e0d546d27e9a0601789f76cf44f0b27d496ecf7a94d070e5087a8d4fd3c33929f3187fc9898b69eaf08a2a491ca3476233f60316dd330d00a89b2f2e10761deb3af954f8218804f979df32897ed6978ac310d587be71696f0603d7dccb004c6104d5efaf93933631def2cba05c64149e854e6f09553e9f5a74dc11b789c60b786c8d1cc9b93224eb6aa192e9f217acc0d8759bac2d5110c140aa300690f74a1fe2b262ad4473ca249ec59ee0cb457a9b3684de0e1ce7176ba76a03413116c38b63f6df14492789c94e00ace049780a31d9bcbb93d0201dac8299d14e7a05ffc13c47424158e6120b51da41d8401844db50b401cb8051ef1c9056b2da469468e89c0949e1d78468ee708ebe644e5fa9b99a99ce7aca73acb8bf9428336c3f14f6c317eac6461f96d21fd6fef409762c8087956e3f754910288aa35b61247d5f61be6cd7fc5e7e07ef25bc05527e455423a669c34471729be2495a660d5cfdb2fd3d0557f98e359a234b5eee7fbea092d0794a95bf0e9ebdbc82bfaa9a0a639e4446db7992e55738fb8d6de674fc7af4b6def253c26505da0a807f04035ec9379329519d579ffa8378585706c42c03c7c535163bc1fc3fcc2defab4de7132e12bd03e8896575b9af612b05f4b1c193cf4711aeafb2bfc451b474bbfd0aab480e4836db85fd225c187ae29ae9a41852911ade635ec0a186d8ce394c8acb21147fd5a56931ad45144ff2a83a96beb4cf569d49679cda2085b5889842e632336ba1f546305c9f461987f197f50e52a97c08a130447fd755f307efc069b85506d1f3cb7824cd1b3bfb73d9d2801a63444a3439be7c3e00675b0e11cef081f54ca32b2ac062b20facdd7f21062f799a1bcfccaf6e2df6fe6931804df988c1925bb23972f4ed858073e7a99068c69c1ecd47c4203883ae1c4ba5d1aa4f60c62b85cf49bde23fa41bd1787cbacd088602864a4ddc952618cea5dc96886da343848257242cb848719bf8338d0128937da9ff0134932afef22b9866f18e3c1ab7ed9ab02c8bd1ef4a27064ec02d587c34e169c4809f54c5455a4ceecde183bd6133acb53b86d1c8637a40e9bf8db87ba92dee40b2fdc8eb41b2243535e31703905751d8add34c7ce4371976b3af4fa8e5cd7c5b9f32bbaad260511e505af3938e4b3db76778566c8d17b7dabfd414f216226184d360fa9546120d017d8e9197b625f6476051afdf383f716ee1cad4213a17321d6d6d18d2f838703b54ddc3aeebef853e33e07edc088e68c781ac4e2117b063429adc12c6b2af73c6187c02183a9ecf05ee1f25785b44c0702e8c686801565a1b4065eed17995ed179f538760ebdc9f51144664ebfee6e5108f3c040d8363dec999c2bb6bc77c6dc304f4c15e032801e550f3497af24d91e111cffc4609c86e4b59498e31d052e39d2af3ec39facbe7f542e1c7d99c168a3e75562fafcc1d4dc6aad08286c39bb7ae88412bbc75bae8f6f707b5e21a617ddc13e469d3c02b327ff83494507ca78e554ba4be581f42be8857b8d5a85fa6908fc4d7beda33eef5e3c0d26285880e160f85935053e04ecf1e4b029ed0bad43f731be52e816734e2ce5754ad8f1b6f426d397868991c74ddf41b917510b9583348390b1eb1bdbbc88136cb6a55b7ae38bdd1034cf4588e2b59d84ff4136934acffad7f4685dccc9afd4d8904bfe20775e3042ee4570411284354df7dcdcdb0a0549e32d091fed17684105a5390bc1e28fcb8a4c7725c1dc1003923b44d732d82e6313f7bd54b310acc317841452f3085733175f8195443ab31941b6190e649468905402ee2d64b851a63fd4f1b25403d259f2b04c65441574c91b6a53b33b19395a9da6747432ad05d4e5451bc5a0bb2049bb1821da97b03f58c57b1ad2ab22d92aea535e49e27dbf4dd9832bc84a8ac3a8827e164bd52353f339eee79d1fa3029d28a43cd1a9bb81229b6c34f656cd9f9cbbeb210fccb6c5c4a272fd0c300da37f7646e6983c8b00aff844655688bc5c7d79f7361c1dfb0f4900d515bde4ea7a3d9faa649c48c51f8edce4b152933b06424812b0f226d672911d9f71d09313e9b623e91bf3febec40c7ef7061d6f340aaea5392ce99df2ce7ca50e3bc1185fe78648f7234dbf477dd3e3e4890084325b74132494061859519f306a899a895e21692d876e34ef77ab0f2b8490174a84c39a328b8eea0301b5b7ca899a8eab23455649eac88bcd6351fb83c79ed129f8dcd8f51d26888a78b88a6e71611e2d53794dda46274a3de683a37490c04c93cecf4dffa450828230ea0ed360565fe75776c8b713a04ed2e6a938305e3c6064e7637b0411a163274dd0af8e68f19ada1082980bef6b4e37e9502efc854c891aaa8e63c0d82c3c6b207b2bbe6dd0662380fefff115cb011f17ef6342bbd1270e4f0f07d5b741b67816e13f2e590b33f4b1acfa04b801910849521841829f50591251f03912a1d7c959a0c3210117f20269aed2ac8e430f383c69aa0b3de61641be376425e572697ab0cd157bdbbe3581e15a084f6f360a730b410bbc7d389f13185f7695fe2d0d840003f1af709a192b20e66b9159e99baccf7313a6efbef812e3882a8526ed805fe539015877d3ebcb0a3faaf8695010f0422b0b251a64bf6466c22798f412510ec52578c0f10f3a20600173b17a117bdc771ea627d67a1e5c19b914953af7ca25ef29f317dd71bd72d42824ba555f8a6df8638a23ea50f8954604845070cbad38372ccda1b7ce5e6fe4e6d5a9414895d6c6d60040e18669ca51bb7bc62dcce2fceec45a9c5319e4f083511a4be16e39f75079570fdd15ae1c00215303b4ddf45786f11509e0cc6a98f369191c51bae5ad6371d8ad34e7ca92d8ba47c1ee8176b2bd6fdd9a1f2e757556c50e5ccb1305f3a6472f0c5d9457263e1ec6b6af278e5f446691ba99fa8284349fad1268771e992c14e82945abecc69f17f13ed286ce2dc4a02ff47746fdc27048f3cc050c2bf5740b953e0d5f7c5e3d462351adbba3f2133e25d82f6e5adba9263966bbd76a6075fb7fc1d93c40d548697962b92f5891938dd53bf91bcd16245c976ae8e4966c13f88400efa1d765d18d435e4507fbbd8ff0dc0aedd45b221150a54d874ecaa423f747394ce45d1a10c112f0b966a581fd9a8c1443717a8c7feba9ad3c19d0448c2ab531582a138dd00bbd93c9dca86d69dfa6212f1d6aa3db61851782f9bfe7fc8ebebc1d28c558b25084c8358c79f1f2cb0c1e22921ba76ea117c2f0fc4d1899a28d5839c896e50d6d4ee1085ffd11aceff2945ae2e87f1515355fdb38af872f42bf6d620d6d25d6be3469a3ad2497c9ab541928c0646dcc4bb6ed07541b1cd326ced3eae38062d033b5efb863cbb3cd9219b8fc0c8e72718b4dfa5d760a9368f90b20d4aa838bf60c1da04739b845c754a5f609f7ae8b37ce58f575327702d134af4a1b720cf0e8acf241c2fd58bcd7a3b06416465420a8b527b00f7c9b93c979f01306c12ac2624026dc5006b64bedfd42dbd6510ae55cf5e5ec01f1cda05ca120580b51bfee986040f4638b17947a102cc9544fbe287f0962ab1e44641bdf68d3bfacc974a93e5ae04cf1e01c93371158eb19adfe8eb6d2300d50d6896a991ce3519fc9eb38ef1902854c30eeca425df4bf283a8c06059baf76374eece6e22f89ba7b48be0d6b2273354428ea3655da803e4954b6ece05ed6e896aed8245e5615ef4731ef6c73c3ea80fbb10cfd33f13630a8acb2bf1d925a8ba052dadd47bad0a70869957a3541cb45ec7eef1518a47bd6d1d2933790db533711aee8f5387e756a6bfc77058845dbfcbe7e4340a4f22f4dc699b1f689c3282c1f418d2e1338cae6630ce213f759212fbf6e131cb904b5ad4db53a28df9f03d1e42302d88d8d1e020e04db9f54090a8299eedca61a28f7a6ae027edab7b9928bee49a3c463cc17b70f80f9af3f31ea50407fd7b36c49488bd7c6e534de55b0f949b98e7118882e24e5ae8f4e3234d52e9ae20b545c7bfed880182704f99b0e5c8cbe05c665259829360e8bc4e7537b2b706ac324457e26d60b3755e534afb1212a4c86a3cbc656027813e2808c30bcfede7ef1a11271c0dee07d547e8c4d0895829c176f7ae61e92b7e1192ee0860b229f4d1823b019b88af94e543a61e4ac92d46718ff54c232413922ad0ce1e8668892dc24d00eec5958ff28cd68001bdb78b323be5c91607c1bad5b697511338518b5b330d7cdf13726ca76bb45848fd288c3b7cd194eb65545db3a2050fc0bb8cabfff1e6432d982a1d7cf78be0edabf8429c8dd7e71033cab7a0a4803934e087a184b0d954edff7142b4128a77a16818c5467a19ae49a1d738fbe00de2adbdd987abbb0c33525d7f8e6c9fd949cdaa00df3ba98828ed81249a81c2e6cd098949d23af55fa41e80238419ecc71b400e339f17e02ba613578425a1ef68a52842b1c0393fdbf95fa0a787d6ed83fa695c4979f99071171d31e8e7fdc74966b282f93e22c7eca2acb21693341676f5d5438f0a63be4f58c7ba44de50accab6c8da26f8fbc3fe12365399b5714bd6408e6ab17d8ac263597568c2abd8ade3cee6ba8ebc8f554080c58271e9db754d7dd59795c20ed80ead9ce7fe7436e13c31ec8babdb9c7328a2dfa8d07069e593aa9bfa63af3155275474103a61868fdd59408cba96cab983d5ece23283a33787785d969555bed1318863dbbae478357867670bd26e37bf8a25a33fbfc3a969d56a019a6bb6d83acdd4f300fe5a4255c4925bce64e21656580999e56b98376342980369bb309dd229f8439b41182f309f5e3d21fee26709bed7d23b39b76ca6ae477fb8976535a20c64b70f1687abde14c2d40ae035992e3730e8f0c7e2c928d9b5964dc1d7635eec07283df75e2a5fc96b3d94b5eedc10d744baed0e1b799abeaa578b3f115ba6ea328831f24e97ea2df1b27e9e39b9a29de34951272dbd761f5d994e5292af6ce0d94ddfda1b0940463deb3c15e14fe99293a0b11fb4e2369a9aed00e353cde61c37e0475af96c7886b485425bae64b85a04817624004c4e5dc97ce0ed25d9a9eef961889752672eed284b539a77fb8d2cdc593bce8257220a2b3805d8ae046f7f6a00fc3b09f5d77c4806f407634ff31121ac95ea3be89810c0b29379569788ba96b8eb18d5c2b0e13aa34b20e8a1d5de217d97c605ed8fe0d64b0ad7bbe93de308f7b9ff4ab2a3e99c084ac666566ead312a9bf5d37061beb23af1a26ed3fedc7e636156a86564104bacfb29b8fa7400e80678c9421fd58a3d9cb318dfa39168526a81b0ca0789b5bd2acb083939a0e27382e9d0ee6b0f264822599d7744f3f77985f324c05323a851befcc073b1d42c30068d748d98ce6ebba19a5bd20a6a7b003060763cefa81d2dfa869cd547c5b9b2a1d58ca98e346b29fbf0aebd31e81551950f86f3a939b1ecc5fa1402be3881eec283eedd61b9178469d5b3665ce4356683d9069581916a21ab860c5545e4d333a08ede9a816f96bb26d4b3400b9696aedb4b4a5bc241981658e06ff8629e45dfa63838332a6f22fce998bb72fa95941c07087d53b37a53f84ea7f9a2b02334c2993e4b316427c7ac25bbf487a17e66b9f3e39568a397a1e9a8925c8dfcbb6e11dd2626e9dae1d6e4984e50b0b9106dfe0ebc625b2640a48a9cc096edf889e63df05d1ea3b9eec3e846093d0f5e815bf2953608971a2ce6230895b477374887a4522c4ec1807546b14b030ea395e10cce49f442d43b22bdf04b1c8aa7e2554bfb96ef2ecf1d3697c447b9e4ea09756c104b6453865efc2ce0caa33807a41b9cb1e2f8e92c4671cd7e08711455aa6b15f1623455369f2c4eac9a86588fc8a32437aa17f6385397bcaed4992c32756558eba2e220539964beec0a6a1f742c5ad2e6fe2ec97d0c3a348abeb7f12b9ae5d487fb0e897f82ce81a02dd190a478fe0e67b9ffea6cbf4704c4135ce69dccc09a12af0c0215b0979068872a8fabb86ec9dbae141503f0f310f78ec4f7e7688efeb550a096fc0063dce2ced7bd660494b1fb7e36e269a89168508470ac320b95ff04675682fe337341d89ac3d2e8d79ce0cf89ef598a35dbcb497ef090431ea42d377a86083656c617bd23dcfc65c53765b9e1be997b31a4ef4c1f88b128d66763786b313e2123f757d3d148feb4acad46ade142846ea8ae6930c2e2c827fc8cb74e39a37f7549e244c9c581e078604e841760f171751650849e9e736b163236004c5b6584740582be4ac2f5112e65a21f68066388e7260b5f700d3cc518fe46b9d51ab20a34100d18da9875cf53d4982f244dbfc7fab46d83693f782269fa2f8fbcad15283dc2d22701e75fa9888d7be0d3a4207dceec609b9a5b81d7fd5ebd6f451b21ae77e213e3474f2ccf9cf34918a856b76ed079afc31cc0e5906c29affd8a4b873dd7f5a9c70ff434e7255e90b10f7a191407b537dfa241ab207f402b0a66d5be805db819a6094ca086c1f71172b47c8f293e6be3d3275ee77d5ce90836f74ef52dec224ea772b2e91b131d30db539b8704c231dcc32acd666f6b54cafb2d594b096bf0067145b9c223c6cd8a21d55e83ea5fa951198dbf8a9f409d82cb7e8479eac2feb7c1a9814a30c2e4d0b016e38f5ef0900219ff11580c48c3ee8af8c3016fddb65b897791b239cc8960d07c98268e1e3827008042723a744a606b573a75d46390df75dc3b3a5a819c22287bb1c562d12157e50fd3c51d84d2cabd4bdce1679053d0acd84dc35cfe562b65bcf91006ece1d7a144f9008610a0c1ba535a7a39437041998a173c69304fdd334d3075636ba246edbbe40d9f637e045a981cea6d1f385744577873aedbc5c1830f53e0ee3bac7648ca9149d33b02d7f80b6c143fb7f0e5965d6c29dc34ab31cf57d5f6204a25b20b682cefea68ed13fd3fa115b718f14a4a33d1b2b6b2299c663acc94eb31a5b38f57cf90df91c1c7eb29eefaae88ab660193ea562740091e0ffe0403b88c0b777e1594f7341688e57bdf472dd5afa1c93e5870f08c69488d677c87b043558fc6748437a217a1c002c62bc9a712875567b4dd7065c625ebaee04dfc6585e8ae962f3d87561799a65064d5bd3948c16fc8f0ab69fb4d52f1fc8ec1ae759cbf76a82b9dddb2fc783a17bc7350ae53ab3576cde1b918ba62de8f7d4fde54bc7b23e69e8ef8fdc9ea71364963a721362fa6d89c15cf4d0607a55712a7d93e416af0dc59d52b95a4e2872fefaf95066c44fdc76de81f69c340b0bf6fb45129b9d1f6351cbeae883daf495221ad6f8ac4242bfc4cf665e65b9140d42334ef8e288828dd095a3d148da2f14370c0b0a18d54947e2af0b115b6e222e912f8137b9a16be5dfecf0817c8e791dd8f1a05eb8df6c433532855aa656dd132dbfde1b5c22573de6ed1e5552c8d974a0e519c2c89ed97dd249413c439d3fcaa5a616e1eae0317850ff07c0d2cc3bc5567f3679b9ce26c7c4e6ef30fe180fb3f8f07cd76a5b20daf4d7523ee3d2fe9289316602231eddb12ca96eb87a194e8f141a817ccd7bfd1a5c5a78c121858bfc99b31348a93594194692b4681423cd2aed94fb09006f1cafdaa945c379c70d44a8e94e18a931e6c9af612347cfdc705ccdb1e1db86e412b929435dee7444666c51c03dc687a3c5faadbdc1392d034064d7be8cc73f34e387b061d616b5afe18df218e27e4cb4a51e82395b5cda4a6f04c91eb905c7c2680882a83fa44d318dfffbf9cf18a6ebf97a42de39d91549eaeff3f8d3e07977c95e9f0704a2b1dbfcea76c25d92b055a3bd27aa2b87f98aaeafd09790ddd22717e7ccabb78ced747450203c8388718ac97b566bae99e93fabf0a9c74c26bba9ddc0dc972abb57b866d1be2741cbffed887fc2da1913e0ed7fb46bdc67ab1888d10ac53a72cc12b5280fe96b9fcf244e6101bade3b4790c175746c69229fa1b4af70aceff4a6d676faf80307c57a8038b50fdb8766af85887688e2274010acd36318d917ca1adb456f2cfaa52dcab4ebbfae312c3e919cbbc901703f6ec3f4e0a73c84b9d9bf7e9ca04be1ceda59e3532831347568424bb03c3eb3e034c82cc1be9060c559c2cae96b7bc172e2a05a98561845b94a00851221cfb2556c5f5042688d8be2be0f509424988ba0087475427e4732eba27677d95169d499297aa7934159a44036e9186fbdfff8d15c7f4c276ef8c9fbd773c0ed8fa47cd2351ee60e4d5eb8eba5e676efedf5469c9042b69caefce8581e32b176bc8d674f4f91b165d8c49a86f50837fbfd7a1487fcc83824c07f37ad97187f733491979a7df722978541133078e7f2ab5576e86c305cc552884b1bbf784d4dc846132404c2900150e69d1cd008df7dfc0e6270e9f1be4c69204dea6bdd322b317a96979ac8f9812c81679f37672bd9233f085917296bfbf01f4a4a35350ca2f32593df176cc5f0ff6720cd5751b90a28ad3c651106089b93f290388033e0e47af3f984959d930d99d7cb9febf3e97085c5a6f4aeb0ee1e817e18bdd5b4355c63b7fef94b00fbe9f9dedef41496db2ef7e8fe287ef58318d28806a331980e1bbfc303146ed8a370501ceef1b272b45464abf370c9c38a6239a502cf42eb1641c4226a6c87316e516a02cb5cba2e0696b0d0f2a4f4fd0ae11f9732318941280ad9f121b62bd5070c746f8b8c4e4a00e7f563c908d55841c3978054e4ed599cdd80b7b97b0cadabb29e6c4bc793863d476ceb150ea23a58ad2ac71f5aa90f07bdef8f594827a9a0d35de22b2f39faa9dac9eaba6de46c80a6cde394d9ba97efd204845a160c1eabc95817ec830ae7acc4d0e01b851f68579f5a9f92e67a94ff6865684d8fa4519fb66147bea26a09f50857a868d5ebb87003e6031a319fc0bb25ce182010e3c8b1ce680200811c432d962149716beef5a1045766f71d15c822616412f004085846415d022241d549ef7ec9fea5a6f9291fe105acb5976f0961215cb0ecf0e17978c69cd3f008636503a83457804eb6a8d422ba8dd41c365ec2f86162e1c0d2121b08533f2e3c0a01c4333bd618f29ad7fc70fb078cca9fb32034b8602e6c2d3b589f0540d3492f33899364b100cce5d54d4dd7cca3230e734cac325ff27909b03a42d9934c2c7c58d5213690494628457ef9a34209bb4cbd3ca17994ecdad5b5fc78652e74e6a5abe7432d189ba833ce48b3f8ce351a1557fde4f596bd8dbc66f292d1c8f1a500e666250db46651c29fc204203ffbb3d080cd5897ea5d4d8ae6bcac138318b9cf6fbc5893a71b5171aa10670e07bd3c3d4c2a2b0825902b9889955a701798f7698e700c218eb7d40857cf166256a4236291ee06687565721b240d0b825dce0506798a71efc456c5235f8ea0f3c222e945445cf6a040ce7fc6b5889637a48d20e8be5452eb8a80e900e160d502a206f9fa8736c7af420d3359b05a544efb67c8c498ca83dae27a0dd20f0e838e4339d03afcc5ffe22aca706b5af90b15d9b36c9c758aaa6d9162662b358c924a1343336592cd5b7bb2651da22c45f754c15f722ae2aebee02451712ca091286eeef7439cc407aed45e4730df9a83d4eb2a611e9086900a7c7551bb8fa6eb5203a91d732ea15efd007b337859155574af81450dfe12a03c4e645ae7591643e4fa60782220c569ec0a8080246cf97d0c98fd03ca106ee2cc3e684df9f63172c832473dfb79bbdb11897d2fd28c6aee26ac0d3af38cd06c74dcbc5ce211eb9f6a3aa7548d70875f775aa4ec65a0354792b480ebf81cf4b213b294a2e76560fddeae2d26f5fd8f3ad5ea916a62b78167a680dbe1fe66c838252809846b68168039d73a52ac9e514c763acd7a3c1ef21791a4c90bb42443fd790a3145f949fcb3b1eef3686e2253fef9a9fe854c5334d69a3cf2f78a03fa5fbaeb4bf3a010ff0a0235fb8046fbfcc66ef9e05b225e4c1f7c096971fddeee5620c9b7b201a0756d128c513c7393ea158175ccf4261f1fd353b85b540167fd583ffad4301af04cf48874bd71abe58bada6bc06b4d5394b4315f0b99e1da9542faa62cd1ce29f4bd2658d80c2450ca625e5f96d97313560d2f19118e1fe9a46602ea2614bb5c6e10efa939482f74a9a2ae43d1ecdd59ee6c067c471ebaa1ad9a206cea77b118f60fe074e9a34d2fe05e6fedca7c32afd29354c8b0ac1247ad3d448d0304982da5df94b7eb56b13e55a2356e7f1514e781350a67aca25ee6a53f3f42db5e6b3779d8fb48910786ae8617a8319811e80e5f321dc0c857f743e126a221e9d681dab2b8cbf976eb6963667e72c5b5c852e1f931155598760451e97ba19cf91a24a8e85ba5bb2befa2148177d82e46d449a675b877f682b47e59f590f86150027d8761ed3fa4aa62a20a761c5d8e80367e70a3815b8e2d81c8a270db088c699b028b61dcc25c1ccc99ab86e7cf267c13799769fd7eeaf7683f8f3caab3ae20c865c1b1dcfde70d3778298ac695731bc4f535004b2f9cea4b07710daaa3717b4da4cb8a1512af5d6a99062783f77d8c9c48079e74325e05884b9a33802ec2db641c77be63b7a2a55be7f9638d9ccfe9b66b69292e82b0a7d30537aeca68df23446ab3037ade7a3967075cf51a2dfbe51176f7d55e67186d301426fb566946a1ad3cca6ae19de11f2188ba92c794fab963d9fcd7dac2b22edae368e571d014c289ff8553481c1e1984d0bfc21280d33cdb497bd14841233619937fc0e95dc32c0af2fffb6354efde949a6b55374b072fa7571469eac9e4a2f4a97d94442bef82b92075aef0ed1d70db661d1fe052ba047a03d9fd40ba619a44e71fa98ecb25101a6e5ce4ace714d04c1c985a95b30ea7b38ac1373ef4df0ac73dc21726561ddc0ea44456ef2f728ba0496ee1fd8285339acd4801c5deaeda09063398313ce6e7fb171bfc9dc6de9a2eec015361a4c008475ede5b76b2e2d18b655144ea0fff8b4c267ccc644dda3d9459b9599119645fe30f660e6cc5d5ef0e7e0be0c66f3e7cbea2c30d4d5ab313d0b04b29fdd5c453a932d1ab9f8a7bd23e940bc96ac56bf570f7912ab930ec8182f10012a100821bd8da71683cd55c896c6df38684c3343283263e42c61aed45f74b67ac1a89227a9cc5246e1cf11e56d1433240d181e93395a22fdc1eb32f2c09ddf7d8badc8f33db09bef9f1fafc9b90e6923a6e7b6fb36baf3823edae614759d9f143e009fd10d40abb046329e575d02a364022b91a19b1a02dd9d7f9478223aa381eef0a10276e8883602e91dd56e12b1b580bef995efc07d1316c5fc111e7e2b61bbcdf6d986a67ca3b831358692d7bda21e271246e097d6a723f9c58330eb7e74ed05ce77f9d5e3a5285fd119f4abcc8c1b238ceb6c96518e16af309df98ab3409fe9491402e4d30ad1c4b8c137d6334c715497732822c06799e15706e2f55149845dabf6c7c9645acd36f2f0ad97b894fba6104b9bd975fee88fc1002e5da0849869b2ae403c5134b1de934ed48bd2e96cbe4feacdd093225e27b7b2407f4195d7964e3ef887e890a38396339489b8a144fe7c168a37db623d3df44d13036756ce57bd0cfe13e6bc40480b7a1d00ed322a991abc385cc1d8855636ba8a29df87503cf3b272706b6cf86117a47c2d51c5eb9b22b956c9533426fcd4bbfc6b6945c536d4cdc2c400ed32f236b2131c7a94aeaad8eb399a7bc5044c743369bacb89288f8746fd6c68f728b89252eaa451644c9dca9048f71c832acd00761f7d624214ccf044495f806629464ba231798ed2ee7e93539d53ea82557b1b94135d95861d233ec487c4395b450da0d8909ea8950518f12309a8b5bc71ea3c564b733d069cb182137e825aece000b94bc452240f8c741de21bf59c33dbb3f0af88788988b413f9b3fb3b1239c195e1e09defcf2877921f9eae2717034c1f92236038b49bbd2f633256b9e01c3897090c183a8ecdd18e8ec8483e39df39a8bb852a057adf672fe9ee3d914c22e00f62cbb7d4fbe0bede6214ab2061e64e38ca0ed9aff092fe9b5cf4261fe701021090873d900b151c5559ce682ae5979e7a36e193655920cd568d2be3b6b891e403d2c787526cd6d3561f44a91e39a80176ac7cb4a3d4ae975d04c893dc64f870152a5421e04e4fcaf4a0571fbcae1a598b10b24ad4fe2326bb6d3d84c88d79921f372f4c87eb67e45301913164230a5546bb1b3418cb197797968be18cf2649bcdab7ab8949c9ed31385ef50d59055044c969e94f53eb66da2ab04796e3c9629b463d630b92ebcdfad3e01b18b10ce8c711a074792f16bb63e26ab057368a9e65edaca8fe26e2f6932093e13b84f0e03ea7a9eb8a8cd49dcd88fc69535d184693362b7ec03b9270bb27a31dfc444ae012183254a3ea2510fc3a34f91f6fd1e3b8d450e983d30fc879d909dd203410ebefc5a0c330d32a69558959b87a46deef910b265cd7a538f16f4b05462d9bae2cdead7f1f05d1cba47b1000b4087187d95168009fb5a3f64960306ca16182b82f1d74084db51a66df99e777428f98a1ec97d628dd104e4812b4e2cc2726e72f9bee187707ff659911ef9a4ddc8281c3e610d33b329b46951cc1e29d50f34e0e696d338c42d40a8bc166712c91e8154a688dfb691828331d23d914b7dd32e889e8590eb052dee5e3d2b02a9472a1e39c5fbba76ce849b87683ab81185214cc570def983dc7d6ec7b204bf33c0768ec645441558639b57a3c3dd5de405897dfbc4667e8109303d7fb6eaedbe6d724d632f4d65f806423a8991419c7b786755b3279d2a342d50bc9853188531e9f3b0a82ef441dd36c3906ebd1b7d0f7c77d422429e8117cccbfdad3628e0a3bd789e43416d318ca99b7dc210da0b0e86f07660d017d3a74af2ebfb9ed07a7acc51064a0b9786f3063a8cf5503802c08bef4469f668a331e0b2fb1fea26afc113632b10d2799cef084fdecf07dedce9a313f7bd48b47dccabb2d221f2a4020b4a164d497a72819e14f4e770916a69363962114d28369670675ba9b5eb742786a59a91f41634650e92c54244ba1abbf0198dd1e7069a34060aa9e16d4be8f429401671d522b1c9d2aa616618c4805a656915c1ffe472cb3f08e3a04bdd72f280e0ed6b0bf64588644f4858956e1d590957d67d53efcf75d2fd859061614237cb60ada4ccd0d539b5b3da668fab9ac058fa8230945697a62ac5ab81a8d43af009de95999cd16e61a3d26c70d53c3bda974f2c61ac2d591b9e78200de079c76a22c40d3e9e2323020954341f84e1ae9b3d467cee2b2795d2aa117ccbfa4dc811c9fc91cca5373873049960a1fabd5c26b04968269933f4b93cc1c9f3b9c1f623b0a9e22566d3d7283a40c64d3c1acbafb3d0e8adf98881ab8be589bbc653bd61e407afa9455c44abe1c04880aa5705cbbefc9e4c96c9f6e4dfae1e74bff51e56d382c8fedc91e176fffd71876a4fbe72c28990ecf048eb8419e3de471fb33f64b4c61ef17244f9683a1bf93393ae40d38a9941df55a15783bb7d766a51efa204322194ed771a320bdb6ebf21a3fdb0b75327779d1549c9f78478334aa5cdf81ec8e8c6e71128845535ada1912caf3e154e5bfe4ed114d47a64473f36ca7d2c7479543256963e9bb04547a2c04f4a16a02c1d7b5e540f7f01e4d5ef56acc45497bac08dbe8eb08566dc01a2887c0f66b431584f61d59c6e5a0d4f8e3879c4cac4697f6e9412421eab6d5542d58d39b92226951881321c58be4ff18e9000843bef7564e1198d2f3f2b55cb8a0673508a346836288849b2a519aab40a7ee8354be49819fa75490ef8ebc4e2f9252df3ad0676531becf16b92c0ac2924514823c7135b5343fc101927ea96548196a778d16f522ccc699129966db81a61ce09f6864ce987f09595a34d4c1bfbf0b06889ecad6e59ba5aaac0a0cccbba4aa388f3f38631c2a3033c2a96c21d1bef46f3c7ee4727ec52781b9760cf40d4ad98ab51331ad8c029236f92bd6b0e40e9ff5ed583a705014a1553c831bd50ac81db6cad4c3242439f0f88cb699623c6d3679770d68167f84c8778a4c502a9ff5c760de4bb7b61b91492e31bef886437235e7fa806bf6851653f755125d7542bc563de80b44060e96c8871701866320af11777bec15be6dbb192d68c8b9b4d7a3763eadc43c6f89d593fdf9dce18af0891b9e56b72443436c59b958888da3f0a665b84e4e10cc9e9769b3cbd1917c4dbca4995358288c5dfc62867614aea0447ba2d6222cc471e869f40b7c291a1985c9020e2644ef5d69985898673b9620a0f3988f0449d7f87af44d17d49856adab0c294833e43ad1a99bbe9de006964ec4fb06415ab384a370217fb2845416fbccbda36ee27c9dfbabbd36b61b6986c62b08607eae1561edbad13d18ce45f82bff486d73c50a559530076a23d03ac7e34ad95e3227264c33a2f34dfa00481760191b2efd292372ed77f519032d524d332d2e9deaa962b0505c0dbe234ea70f6862297a6692ad20324816562f029852dbc770257f05b6f5932ae6c41dba5669ecce0169113ab3c401ac8b61db29e684f9fee2de5ae3d138d1534329d4ae55eea1c0058a6e9f361dbe3dd9bccb3fa671f2f4751c9ace78e624778fbcfaf7ce8fb59a079f8cf3034c7cb0e9c575d865587bd6f932cd385064a3543fbfd1789a7edd0468d928f77fce4a6a837c2a36430a2a391f1d7c55e3aec0afc817fdf96f3b23ef23161914ecea4a7f35518f7412c18dd94555f0e6ae7dac035c70a44794d8d90310064dbee6dbd5f1e127c457664e7ea0e33d4b12e24e8cfb2d1e95f646e1561c30cdf75d5cea5804873fcb26ce6736dfbf3a9610c70a9bc16f3bf3a7b8636b85c0e2ed98b33e27ab253ea4101815f89d5f035bd1fdbd6e985ea6216aa00785ead299c4d44c273c8b02ee07919c68b1406f8c8dfef95c69514b34254087ecfc640b33e2f03fb46b5d9794f88ec96ad203253d10a09a363c4618ac0316e84fb3e1769beed4d2cc56e9a95a30cd66da70aad7fc56e6123747e580209fd39c54d06e6f93c87856f5e84ff266536fcc8cae2ae2d7c29de6e8447dd048368e2ca500382e9ad3eb83b213f6d63fa0ed3bb0b21bb708b40146fb724e6e24c0f9864ab07b76b7cc7f1611ca1d937c85a9580363a34074733d74141e355116ee5ae19c8dc8dee3ca7eb0a9d1b8c17f8dac66c36fd6d486f9193423a936b6d43c29f92cab14e63a59d533bb7244b34e0ae749611398f35ebb45ef27da030a1be789ab278e95a24e7ed8f0e48d25087f0fcac7395cb3b27d5089c98b34c832ff717698f647a676bf15c34ebac32ddec486f81c05f6d33e90b23e0826596f8b647fc6f73f0fce96f5a6047001ba36fe2d2f6c93f4d4e23fa4db25615ad89f699bfbb546baeaac7babeafa36813a276a285e06417e382e6d9db2bcc8886c74c38f3040a2e61bcae0e8acb189d5d5faffbec6829a596edc82a574d079d227fbf83ac82e7cf551c34cd4b8f0f5cb06b891521059bb9d10284874216c908e2d0ba96eb062435832aa12dd0f856d3e3881bb50a03933aca921b8483aab3558733aaed75d3633e0d50e2269d0c9b2a22db76a2e4e00d070e9695fd8ecc39192f49c05b93d1b297c4b40685a581b27c0661d0996386fe449ced3fea8ee938588f09c041906afedfcfa90d7c8553e26a957cda74199f32358d5f52c71a8cc390eb99fd0454a8664a2b838ffb6552e2a1e4e8d68de300293769c14f6558a4d63305f534b0d69cf543153eeac841e0ed0dce6b77344b7b5703aec90177218fe8684e57a5d4ff6d82c65a27f4815750ffc546ed5c01f59ca7a28546b2d126662b58060980a335a425b9d156ec8ac7cd45b6523594cc2fce80a4769b4ec457741cec59887556950c0b233681e2170747878c1f8578cf4f993eabf2ec6a1aac9ba68180bf00563284daa4728a588479d6f2608f93fdb979eb8244bd63fc36bbf432c9b75040b571f4d27c709b646da8f711a3ba1440433502aa779159728f4e831dd0b0f8bc6a90a16dd3fb39df1981587f7c348e83fbd03caca916022681930420945ffbe66b52ff5e21a288a9f686d60c3c2030d01617b5144b114c29d3d8b52069bf0b77516939257d11c5347b6eb584fd0552d8d1d3389d965be106f37fa4ce5d3d52c00b9397a5faec4c17fcf1eb1793f48f7497f891a704c4293b8aa65f5e10c9f52ce518c7dd30a300e9a9f60de466576a1b16b0ef71f583fcfc39a5712e2bce3459fd6b79448f996b499d86b43b95e9d85cbc1f5ddb438d1d7ede4fd1ae91fda64fb1b71d0902933ca2a4d62fae3489201614150fec119db246eba65dd64d415ec480bea8e7ff03eed89db7a62dae38c0f374784d0445ecd7f4af5412219087e7b6080bb5b8cd2c20836e70daaa2da373fa28e54bde32cd077677074b0a45d4497a875c753d65105a0b730fbf43b3ac19dc33d3f6aa50817ee9b4efb0d4e35a8e8c47958bb39812cca581c9ff5863fc3935459fc00ae8608cfe2b72bd7a288f796cc4860e981396084d434b67bbca7d6d84f5b6a9649557a93db59635aece1e9a59e16cbb671e244a5340a80485ad76b0db8b68a9447104040ac98175f9df57753073afb64f6b759e31c3facc9a5a82da1665f6db9dbab66f1f445887da22cf12e5a3832e6d539033851408e4cc403d72b975ac0d78776bbabe767078a5c9bf9c6a16e088c6268756c0a3e32d32cd6c0345068dbac4aa3373f44a81eefe35f517e315d3cd17361c588692bbb9aac80a6a7a3e133b2febb94fdaf2cf120487f162af9fd281295f7cd7535dba9279aea0f84dbfd3bf6b1691515bbd114a25e6ab5ec71d63aa63912acbcbaba67f2260f9cd6a0890ea6f1cd235a00e0774531b07716c709aa192b8c3c73f5d37565a9a7d233ce074a6344f32dd5b856c9e8f7d8275ca337649ee1bc945aaf868717ab51a202678d353c6efdb22614f127348ea67c69de20dd76c94c84b8763aa174213f97babfdd01119a6763fe34ff48e72681ba851ed8798ae73e36591636aa0d9ab6ec70df998b676b86bc3a1e56d4e46020df5b4392bcce822f61c3b8e0a93e0d9b42bab2f70d6a465b333b1ccd1b2461c46b8fc0d6dea7382b4748cf1f47313be07f03f29cebb749409e7dcf3cbdbbba2bb1341f6d7cb2b9cbeb26c858c8143f09647c7ec3c9a6a2b8bd06937ecbe4b0c18ab6493a46198a71f7c0868c2db362c7f7e5112075774b08e5dd73c558711488b831cb8f3f03f968f6c0d36bc3b40011fa67ea9a215a6c3f05352b0ce5539cfdf78fee8b8291497b1495984f29b5790f8fb2df2f9c10ac6d9e7e03ad895eb2d37ed3e78ce62afdd4ad3a223cd6d8228838637148ac4dae17b9c104a01f524eb9fd4102fe7baf9a105ca4f121513be41be3485f94cde13c15406f74da5ac3912d25b1592502da14a03c0116b9276cddce56832d2018dbd6b9e9a22cca6d205d8df0dd64f84c55f822ca35869cddba5a344b464167bbde8ee1513e6f486449f838f46cbb22797998ac38d12c8ccde9b21771bec572889db2dcf78ed5ce4a646a221ab38873153d0220e130f3692ce9703bcb5aa68f5ad5aa58ba061eac93bf3d85d3aae0abde382f6e8802c47fac2db116e75141af0d01d466b81e4caa9f93e1bb648762ece42df9a9d4ea340f121612305e9b1f4104e89fc2d2276a61391443366317f1b320bf5883d7acf4f1f2d7824a5eaf177d751819fbc8a5a067e5c905b73de15ba861a0471b8f792caf2502bf34c8d4d75229af9f38231b9be02ae174d48e571abcb80d48899e2e5929467ec9a7a329980eaf5f3d70062f0771ba974ab5a0eafbda0983e7850236058163be18d35682ad3ee2479df07f053ddb287d618592419de1d23d08617c23c3874f238ff4cdde0086f5b2604882639142b5d345b686b0f2e528c3a76db1ff2735a3b93a5625a40db0e910fb0037e99a8cf2853d9f680777fa8242cc9d3202f908a99856c60c433e1b63310c7c741659be64490cedb2d493129e97e7d4172458d005da82618f47b0d5c86aa381dfd7e3d8492eb1faa9aff1af1e7f33f6740cb2714e6cb475424b8a5f46c02f46e60e273cbac7f3ca647dc5d059eab67ee1f14dc1fdc34b3b68561c2b4ef017beb4465b0845a930ba7bf86dd8171657f3a9cae58963e50c04360a26977bdd364b24fa2d04e40df19e62b8c2ebbc3b5252931e1816d7832d8d1aa410c2aaddbc8c4df518bb6067ac6b5daf3aa54219eae5227c0de76096b154865eaa96ca41bd34ba4d7dccfdc26acd7d52d27ef7a05dfb8e3a6e5f037bd8de45b5e3ad96366fbfa4a23ab88f61a96b2171b9a5a18b787df63de2a8b933d7c5f0a824a5f2fff33d0f20117523963bb471cc769bc29f807dd1a8902b7522fac04c3b655685bdc49d0152b632a031dc7023a5dee34059101aab943d958a49575c1730a0a50974b6be9a1c89799526f3ff04c036cc214443e4ad4211a8d6775edac2eca8dab9ecb9963e09c818cac37a9f7c7e9147720f82e6f3fd1977398c192c3ae547e8ed2c976418fa0022a1bb19aa14d4d3a3e57555faabf9c667998eecd66b9a88ff9ff5d85d195bbb6cb5a59d588ec66bb9445984b05f94b29af21e637aa27456c952ec4417671908367b681fbd461841bbbf73728c77e1928eff9ee1e387874669fbb86bfd1c64deacb93f92a0519094eb21b9c768c3202557fa6b3fdd16222de6bd72064c37ccb73895e5056906f8dbeafbfa9fed5373b556f3cdc5ffd6fc810ea1d6841b26b11f8902a9a81db4c065d77352ec4679cb1933bd3a26042b9015d05b3f06c8ea9c4a3de950eb3e2243438f9d833f62a8a64e60081b184a3dd80c5956ea4382280154ef772acff21dec3c5367cf69ce9d3b3eea7199d04746fa493329231ac498e79d91feebbcf1c9c69f254673eff2a38a2c88c9a46cab31da5a33798164a0479f73179688c577ed26cd1a1895249c5b0b4698da2afedcc72d320eab2a1f10f72ced9eb3a2f369099b591f382c164938a575d82f5c74cdc3bed5faef9d2f53cd67b3c538b0a243feb592cde93f1996a009c27bc2e17498a12f2b31db757ab3c75c3fe94b39853108af454f5b7a1071dee2b873e7bae0bb5561163212f156dd6cc38565a5df67efc1c5dbdbf7db6581899f39c523715daffb98dfa451068ff3dee2d9cd846e6fb7b2985ea519f478b606c7eefabb39403f85d0abebc7c46e7805df0e0ece419b389f92558119a39a40f5ba6aede141d72cb16f954b5d12914922a84d30780e7b1b9ae2fa8fe37a715754ef4c5847d58619fa84c197ab6f1823cf9d58cec3de10331c927566aea5372be65d5885b72f623e4dba6f20939e55d7f9d8e4c78cd54e3b7de8a5d97e704e1df21b6c57caba667aff1ebd7cb85f5ad9d193a9dd800776667e587e3b2aa790830a89bad3068130264597bc82c6b7ff41e8bd7332ea23bc4f8aa2bb5ab77ea9cd9907fbc6f182d80b10a38bd94091e83c7c76fdae144887374e9085b99645506cb04a4d8a3ec646b5b615ba86dd2d14a8a4b23a17c684371b8b84e02836cbd98d7cf108eeb2c64b2ec21b5243536483741b34167cfb638184777c0cd0b5a23d420201ac5e3d6c220df05b3043f936747161faea00b97cca14902d7a2699d993e40604ce6c8140d08b37b10e05392027d3e2ce2c9f566984f2ed0f83d96a64ce079919cb8d4257b84675ff46f87e36f511ad29a91440a2c652f4704b8e467872f252e554737bbaceddf554bcb397f116f7c71b26c3e49b67b21612f1d6b103a262983f3a1dc372569ff4ffebeab49d5de6694c49eb77907c6da62d16ffd005eb877426adc5858f78533216787c4baef465a9d4ea5c8f37d385a5242ae851b8b21d87814ef95229d6a8159e01cb9e34843412a8c0c78479ee64aa5efd56e5a6d1e036059e986064b6ed8136cffa49a2d5374d2abc9cdfe9695d88c83fde83c9b230ec8a9d1bfd2eb207bf81f07a2040a66a137dae663eb1f2ce99dd61022a3f6ae214de9656ee360d5312bdaad571095f041166643356779a75b668ba4015741ad4fe4742840e7f2bc2d39ff41212eabf637786bd04576e4a9fdeb427c057a686cae9e4d347b76fa3d8adc32243a32a8e0fc8e42cba4c5e6caf78aa34941bab1a8a2a30d9057267485562c3d56af58de8216ba285c1aeda7436d067a12c0d8e84aeefca2457e1092cd0f5afc64f1457c044beafda64366a253e2bd84ab91e1d176bfe608613581a5a9131567336ffdfa46e5637f7d2992d3e40a82b5b2f32f12418a12ae24c65a4a90b55fe432b9e2ec331dda0d83530b608357430b4223e6d286f6505aea1318d5099074dce4764fb92ef079865851e814bbb5d792c953a3818d7bad2aeab0f5f99e810d19a2e4c4249394e29e00d8e88e420d965ce3c2964f015ec984712d30e1989da721d4d9037692fc8098d08ddde4ad417b659e6bc78205fddeca065e322df25e69c213b3e4bc52571ce27889aca06b9704ff9bd31474b600103399c13f72d5254b3f60f8ef3f672af565d0268120a7727a506fff22936c710a0da732ee8a8229d18d50aebad47fdc76e218e30cfc64c356b4fe3c1b8105a6a0ba10d2f7b27515101c15edce93539a21ccd4b77c9c8f2048b19d0727201fcfcaa9d09796a253f012a38d457eca7c0b54d22bf9837ed5adcd34dde58e94a0f1875fd586e0cf922a1c8b7c4d5d38961e5a09ce47103240a8b6d8c7a626a69d554cb6ca87f78826c096e24d26e62974ee906d029b60ef2faebbe0b086eb85803bf8df03d8449e0e6120375899cfcfcdd3d07741450b9ae9cf46770613f2acc4bc0baf3f4a2497fcfcf3fd2f3ba90d647b2504d43aa16737fc7c36388e79e59f15095ae8d4f6ddd5f7f973a7e7be3a097bdd91da17e723d8dddaf3ed42151a98d89751e49204e3e97e780b26a3f25c5d2e5c3b38bf5c5d84e7a281895c369e2f07ec8ccaa7d273f57852b37edaf06436a34c7db7b15800a6e68194e616a08fdd7c9fd73611e0e8415d34285478de708a349f997a43d346680778c5ba7254258e11b923c1e80d6c87657fac723c35ccba5ce517fa79b2ce73c9e431fca8ee2bfdcd29494654337058181befea15a8bbc92a9f904559c4b5ea515a666d5cf7e08aed391597e0e0be1bd94d218e3cb98789e997a5f6762b92267279af2cf624bfd20079923751f01fcd9abb01f3ef55f05f09835818ca5a96eae30165fff1d70dd4685d7c109defe71fb03e7c3b4bed4534e20b67cd809531ed07e41e69524dcb4cced2ea5b8ccf3444bb512806a18490ea744ba0fe46fefba439e6b836fcda546b6ebe0d9f0234e4fea1488cf60ba8b5e1070645fc6e448f876a8e57f9acf8f4aae9efdfb9903b16379b6857b675516c1b701dc28f52c26927db4f60e5a5bced6f92330d647c471770931e114eed579320b9114e0e5ecea06a22d629f0cb9ca1793a3ab715d9da4bcc673cf976a835517ad55e6b28f8daed0036d81d40e10ba415d5f6a220c87c95c69ca120233072a15776a78a39706b651b5ce857ff7a046d1b47debdfdc2c6854eb088651e387348aceee973e4e93768276e96c589003e9d6dbecf9297ae83e3d9ea0dd89276fe98684b03965d5c77cf7b57345df51f798ecc217c57914ec4d012c47f8bffa562915241d57af749651c2664b1b785c212e747be6e8285ee2d46fae3c575688502dfb18b1be54241cfa44da16048876b9dea8ab51978c45d4936abf8509a154dc6b3af5ce6a523e19b7639934a3bd5f230abe5e48e7740412f42d029f716501a17af7b9f704f96e6b460fbedc33ada245c4298a2ee6f376588ae39290696c9ecdbc1633c48baddb7625d5004f784130a6a40bc01913f840f9c9eda20acb7f30763bf2f738368f6ef4e06dd4052dee267af48c0c4dc5e605d38d32ed146814a3fcf400724ad83fc562cd83a493a3f968798882dc9cfbc72ee93840c90acefdd0a903e0e4f41d25c3b574e4cbed3063f18981c286cd17ade11d752f8c969f4f0d99103d47894d93d9a55d5373aff6d8d7f3c8629cc8f877daae3a3026a0902de08ead940f22981a52e36614d4a341ff7effdd109f032b8a94983376c1785f57426500b280d01630637cad2c936d7959d813c1d2a59ac0015b23f7a1bb0e8c8e72255225136d37c2166c228f970bc31a23ce18cbd4cae7e00db76339441d76a67b2bb7505072110d3187c8ae5e79ff7cf1195f5e80889e5beea8c9f6d3db77512100df82cdc462bc7bf2814c59ff44825ad106e5eb9cf5d7f9c180c6a51d82c4b38c799823d84ed5644f0c7917b827b75ed695bda3952aeed6bd36ae7d51e88e87eda78fe9b2df4e2cea31130a043aa8ed4ce016b8f661a1f9d1899dd4fe6785d182d41d92be5daa04e2cbcc79c65181d322c2a87a94302958b1d6b42d968457f601f6280b8e84252bb69802fa7470ca928c4bb5b2ae157a4992051067b2179eb6494f2460ab9e109f79e39da1504b83bd1a0ef7438a1b8a8fba3137d30fb4cef61cfc022863d6139de70abfe1a386d5ddfa8829621b7abbc0fb4392a6e70ebf4f757c30933cd29c1ded5fceb4793dfe7e89b325c8056361cfbda75bcff5096c7ea037e716878890aacabd3de6b44cc1353f30699fa76d3568828aa76fed07cceb80e4d79407d0e5c6a8e2336759339a02d54cd299558e15e289849fff42337ff02230ed91ec3ba41545e660b2968623cd1d2ca05b2b77c063f05c83af7ab531ff7a5554910c418c043b168cc9a3f77052e1f3383ee7e6f5859b471d807e4cb60108eefb66a96cb6cd1d8d93e1c703ea416cab3af3b2b9da07628eb4e18e4a1958ed449e3c33b6cbcded54bf8cdddf502513621d46b0abc88673497c7ef7ad45551156d37496e8ae13362f2ae1e5416cf4eead3b22ee34ff1f8604d6733b061330d8d9dc1000b6a2808ee6491412e92b647bba632379376ac95c6af60fe626ed8143742967d5ce2e03522ac25c6a95c80e7c34205a06da6ccba8608ff87f2ca02e48fcf98df30b9c7972560e8398fad4e0b2bd3408a25262aef8576a8d84a0f0c9cf63852662eae015f1d00e72067b8f49bdfd2f97a37093e916d4efd9fc73f614bb4c0be27b45dff15524921e39a5c670d7211e2593c1530c2028a4d1834f72d1bd0ae9c3785ef74e1e4e364bc5f834729881502e7fdebca6a8a6b2bfecb4de3ae0cde3ed689b86d80d2e80fdcb088937ebd5eceb45fc7b5551d3f26fb4e63ee125b3970ff0cc3cadc6120ff9980637123e3c6d244f1e8ca37edfd18c9e93e79500866b8ef4564e213e2d84150ebb49c02b35f7a0f35e2dae129687a825d9ff9fe6e1dc8666eddf371dcff0f3a9093421a39c64ff05a20fd4d2e49e892ecf5d0b26d7be723f779dfdbee8761fb8b81daa95cfaa0014f1d223c020d646e94f58ab9f8213f9c6b6db07e48aae3fd86178901c22585cbb04145ef746a03f5c621cbc5ed11c592335013ce542449f99d3eb34f334f5425e14072168d472ab045b42646705a752bd8e250c054cd571abb151c992c47082b3aeefb6d1d817c4de05b0124a7b9be8005ba6bbfdc07d9ff5fe8d1cdaf8b31e1fa4159ff2052e487025dcdfe011501930c854a999fbdddd5d86de849cd47cb9210f2b765dbe6aa5dbe09aa8adcff52edb36f32d0b5c791cce6ca3f7e922eeb4625d5bf4a136698ae0b36a40ad3b2ea610a55ced68d7ae7301f28c84608b3e51383cc42026cda790d534390e618d70fed5ac397ddba5f5cb6300ef59ea441b3badb61db20fdb27a366b2f26086e6e64cf7d8ef1b52a2e364c2dbff31b2fdc8b1809a98427f81b4beb6fde0447785c6225d3ddbd74fe88cc95af6e317abf8a423642a61c1d17bfc16ad9723ca8953fca991397870d2e786b742227ada15dba99b37cdaabe2f5a29d15fc1bd93fe0cf19a5efd30192a8ddeb465c8ff00a3c948ee9e50b68820a74fbeaa9ef598351528f74def6180a0b7974074ef4aec1e7466faced206cf1d1d5e34d52bf81d30d5ff1efa0158586efcca3793797716144f43974b0aaa0b048c9b01d4c4b5a2295ae793e1d80e374e3d266b76a7069994783c8bb889d38731751319c256f632de46397c3f9f3d4398c2f26111c743537c39420cd321a0bcc9f810b7df3138a17a42b4fa74ef177072475b19e20a056c14c6eee564e1777b2592f1cf82cc0382124b33ac000e0a92b216f8f7c9516c01d21f26a591f8b6a60c10d308cf1ecfdf838b4d5939d7a99b744bc7b98dc34842c373d636ee779a57b478a80ae03b160d8e5fd27c3eb9a9b066b3a592d6ac1777fea48d6b21c9a1db487071f8dd7f665cbe38c7905e5f1f0e498e2146014425944e7f26658b3cfb6539baeac3e630d6fa969055f0293cd56ec40af889c44d4366c1b1ae6d68810cfe63b209eec4c74376af54b8c23a6c7bbd1559ccacba55304ede0b9bafa51d7e56856a6ab21b604c1b02b2912010726fafeeb4563aa7622c6cb3e40399630c4bc89f14eac2b6da26be5fb178fbb75157777c241fbed0018d08818caaf74aba002907e209a2b4d41b8ee5021f6d7040b0bde4e29b6e8bd92565b3c6f6828f171dc64d3f5501423758b6d51eab996c53603b4762bd8be439822c7c978efe57dfe40aa7c2bfeaffa6bec8cfe77e82bb1240f1a6ebc253745298577a1e47ea6d811cd1c03975500b73b09726386635bb3b0e058f3dda11615239c5b0897be69df932cc284c1bd3579ba75425b6cd144a08b6e0f838f22ac70872df4c0977d573757427313fb30612942c6e69f8e06a375c593632398cef291d6be426febf6d09c537cffea353b0076eb1468da0573b6f13c990df3a6f722b0736b122998464e7ba6f3d9ef3fc17f56ba4e8e9f85a201d6dad2f9a8d545b035101e8e68b930022160faaeef235ec04c6229b1093149bdbcfe36b29897331035b839e56f9b07225ae741d05e6c6829d92e22b7582a3e21791b8955821362ff39893e8ab674e1d3c98b21addf6645574d50d7ff9b9967df99fe982a94575666ed48c0e1a37405f9d68abfe73c39d64d357d30c6440f30a638761514a9b8dfb9af7321434286f41bc47cf60288db877191c8f62b96b59e57949a932bacbbdf7e21fd6c44cf2deb2f4ecdce5548eb586e447f50b8440db0591e663841e7d180ffba080dc00e2784c2ce88b5c36aa6e4b60351d97c824b591a0618a5305f3d4e39630b64093d543154894f7d312ba34983db766d219cc898fd376c9479486c778d4eea36c992be3ec1070e123677d33dae50f50c9059bd5f7074d624cd87bef44e37a266b1393415e00adcda1e6c0687764d70e5fc10eea65725a8db3845775f3b06da9187a00c7c61bb98e2fd1e76b98fa2334f79a0ab4d58da57bdae8774c62cae868c0f2b325ce181dd44a4f92accb5ec1a110ca2fc18fdfcdd4818b57da9ffc34d8ef7a7ed9a01040e297ad6b1f4c3f6112205c178b0f9d6f8caaa4e4dd6b5a539fb647d532413f18cee5b5f1a3a79ee5fdfba328c72f009a0ad9b09f7d55103fb6940f2e87d096c2b22875daa03009633589d4eb353c9293df4cb906e1ed8fdbcc0d5204ab5c464b491f960fadf408e9e0a2564d0a49799347cd7e760613bc719dc4c016008dae0e5f0a29a22927921c7692b05394154141291bb00bf6cd7a12faa7ccbffeaedaa804a75a2a8d755b12cec98450d48421adc3cbe81dbea02f767e787c0d9f2239324e311db1130daa02f08a8c532a19018f565ebca0f4a8b0e9524c2b855d0f9eda05588a0e8742e091c0a8fc471d796fee73df99813d438fef25ed61b19d102abf31db5086a375611da84eb62cea6222279041738523a9a9d54b5c413d516ad6727f9a286e115ccec59912610eb4fc1eaae0adec117e9fd73a16d9281ecd727aff6635fa6d309f0b7d15a62a33040f14258da0bfd2672865b1745c7a4a78b8294713ba18a19247700292518f18caddd2bdff01b07d2554f19d54ee8fa472df1481d0169e7e68f48cfab0c26334f9b47afe3d1036924523099d298f051456f7e6f03297534f68f42c91651eb7080ccbae620c90066245e105f548e189a4c38299cb365830814e098972b693fd8ce8c6a253c9950222cf086cfe90c0a1550dae95ef85770aac0b352183ed2a432a456dd080f9d0c38b7b5b9ad8a1694e3f2be15ad2f1b7cdd3a3a125defb74b4411a9ccf493c07eb8bbb77c53ede97ad506b87f3333d2875c36e2459a07fc1bf952d9439b169e04e16a0e54f99161ed3bcfd00c9983fec3a5b60159445cf39a146346291c076e9e4b06e675d10e962931c5fcaa2eb24a7281a333cc2e91ad999953d146e28648697c9fcc51f73e4b5712c45a115a59eb32139a01538610139c136b13f7501237b1ff069b53ce3c3e3d8dfdd40e9a06c8c1eccaaf7b3cf7f9424af4f0851362fe0f72cdca50b49d92da200ba70f76831b8aba15a2319232cde14425eca818ad64e4e3461276b98bf3a009ce21f90f5d1de983b80cca9949feb0f42aa9d6f0a761a00bc4edafbe2243aabb774d373f3f481a602232bbd95d7e7b39e7e2de95fba01083c717eab62a2542079c34050826a07690d4b0eb968acb352ebeb1420a25f732811418b9c4bc7643b0568999751bff05dfeef3dddf57b64effa3c582eb5eae131fadc14694f195bc6c34adfe6dbdb6d880a777181669101471d3887122132af346c19a78157935fccda4558a62cea5c1f160d6ab40078e12e78b3185a2b98161e4d5a898f3b8d2fbc69a8d8b61cc1b4a7ce9d5a2271e697c8f8a01d4c06ae5a5daf478497b8a8d74038fe852f15937fffc8838a0539280aa92e16e770e50537fd5ffc2d9c626d1050935e168080647fada8d44e54551dfd42851708da28782902bcbb210e5216891e588800eebee80f13562b6c5d3e959d66089a707a68b69df2d9776985adddf0bab420ce467b73de6604fc8edb8c2d9530ba4a1f3b9b1efd96674d6922846bb036f8224e58c07b580bf7c65e19d540da3f19a17413f175d36be7aef11c5329720af78dd089f7061e757cb76832d2535af4e65b9881e3f36f6010896203e0b48915fd9619f774bff6cf21bd0c1b1f60bf7bcd3c75aa8238e120f41ab95b5797d0ffb37b205c3b04e06672b8507750c05cf7c2e65a777c35213157a620767557763830244580a12c378cdea9b457f0c7e5e528b7eb7a946a786a416e88da2c9482b42265092459c4d3c25a4743b030039466e10ab48c8403f744bb23f4548c0004952ee015f7a62d760945a22ce74061c3d303f97726c60f117b5c93de86401055a4b00a2457c5b8b86c7493c1aa04f84dc38b870511992d9abc47fc8b510ac85ac5ee21000aa1ba63c9585eb2b0740b3ae29b6fa39feaeddd5809e1f144f22de332c79f157bd4a6a138831b06f63ddbd044875efe75fab66aaa995d54b25915779ea97dfdab0e6a3e97c138811cbf12c23b62bcb140eb8ef6f191d23ed7c63b8dffc79f273794ec96e9599be8c0b515a031fc8a7fff41f9fd901bd41c17ea3cb4699334f869b1e2e4e2c6f6881f4717ebc7ffaf30fffa14e3b974a9d3800605b023ebab1a119552e2c97e13718d5ae53e8e232bc0e88d8501449d4cb0df4c0c766fb5a46c207bc72bb8bd68b0a607bbbf3847d55b956b973b3ec114113626d01670c26dcad26e6751d9b16781579668b656c6a86a56759f7985fb0157fafb859fd959261c8659328432a65026e3f5fd10dab43db8eb93a442874bacdb388890ce97194749333ab06d57e76c387c2e95e58ce783ef30474f527b46195a847e65e169a1943137190c2cece44cd0c15d89eaf242c43a4a329ff7f2c7004d61b832f2061dfe9d8c9d412e4609fe672a357495408a9c8726416d172882775ddbc1f6476c7d3cac15a3ae4dc6b5d9f22c02a4881402d07f21fcefa4afcfc16891ee1f36c1e7f67bbdc7dda1b0dc1f87c9fbe25217a636f18f2435707445f0bad13b8768359de9c1846e5e5c43f28c079fc8d17797a7f3d94ec264d50191ccd7c46f26b04f3570fdcb6aa31118a8501107e2c7d476176502ef1494536f1e214f054fef0be0d9009d0b9bf8502344de5350531d3bb95b1b3df55bbecf6489596ff1e7ebb55bc1109aa6508138e7e3c36d52de445bd71ac20fa4b6680e87c70f1c02cda651d0878df400364524c0c6f6ac13d0dbe9f450e902bfcedda968763a4d05a7702b69330d4ffe68394bd9caa4e4b54ff6764f9a0d5ae4cc0437066b3411e9f1fe5f11eb5b6b3dd5a9882d33399f38da838bd81de7b76e094a833e5cb218eb7ba35165bbc27b5936c4ba39c76694db817a36285c2e64b581ba9f05e733f0ace14dd16a5b800e410984393e2bdd84a8f29b551facab1feaa6eed19b796912a462a74d1cc7c5e32474b1360cc6729e76bb9d81e8e4e0cd3833534b9b6097a74a483bb521e2c2400e15ba600cd78666a38858ef2d5bb768c7b3e23391298bbc10293ddc366db53e36b8ecc18f09851182b016591829f894059876ace1fc2e8a6a77c49442b6031db0441f09e299e61ec223f7d37a155aab58164c80249b8660d0bde7132378e15afb7e4216b5d37bf64d04accbef2d63b909d054d1d515381b4eb01f07a59879e2747de5715587cbaf2b93b112dafe7e93a2df060a112d628bdd10940cae3d719401c8059658a67da8fbd03ca94d56c423ecfdd7a45be2215d3577d79bedd31af5ab6ba7032ab63d2131bdb97598fb3f051b8356751b4fe9ae40fc547e855ac1f481ef1fc3843d86314bb7e1a394591e6043aaf4597389184f2ca9aae065ef55e4f3d0623d74ee7dee9a912cf636a2b567b5744652c7ad2141b28dbe745c27bcd0c9cc9b45f6d6cc770f5bf9676f0b99a1468ae4e14d85901eb4d1ab820f452be1f9419acfa489d8aee23e52a1aee4d2e94219d9fac1d0c677079d8992a0f0d564421a40a993ccd511d6746b160c7a1b9cef4195dab2fba52d5e1a6bb322c3e67fadef2fdcd1bbed61ac4fc72024585f662641b231bf6c6ed37a332f278ad33bcff4867bed4b6b06df200361a86bc318de6347567bc353c47ca79489d8e9509d2e15d9fea0f7d20bfbe845b66d720f2c049c7bff0bf38831e7ccc7dddf593f132b284abd24dc32e0754f8c37d3f7d9606e8a165198b18d6efa7838e354c7e81bf906663f5a685674cf466126799f446e2ad8b33148cebc5270037fede2cc9d998f3d45481b385373f3ab3e6445d15c1da1be2e68b6045101c4587eabba9be00c5e4859edea08a16fd3ca4b5b73409e2b68adf48c88188edc37064104f453db28e647d4046c26bcca17501181cd54f75bc14c68f8d97014e7a7218da1bf8ff05d5707127004ce3c565aa95e21946763366035f6b614e5608405e2b37e26c4d716f048fcb81cbd273b091b30cd47db2501b85b8455c36da4b2e29536224fe75e5fad15ed26a470b8108b7dfbdb84a7687271cca0d8654bf5835952d575af659030e132fc05a5dce434fe19751db047b8d39652b052d31cc8e0ce828761bfc2185cfe93f3bedf8495709a254fb2a018d1b6eec59cc1b94af3b4bacba4a76c0be80c97f1431461ca710656ac564f21352d76312d684c9eb3e289b0e85db8fafd8b379c284332a347f90045e7a432c0d1e1c980a092d023a03ea46fbfaf4812160bf69416542086e9a69551dc6d31df6d244a40abe271d4787e7ba6b32cc4a671365b0ea95f264c98b9c25939f435ac6f524ab83c4553bf7bead420414b7d1fe7bb9fac5cf6f6471f3d902375daef86eadd4b48b386f90b43bbbe4d543c2bfc55a294d5beb598701b7d0eeaac07606627d64b01a7659e9c65f2de1fcbf86a37195d66ab718246959912e0be89237154821cee887d3974770f7811759e7754e9df09494da47c1fa986ebd91d3f3ee30bd4ce20f68b806b9a1fd226e5b67a23d531f9a6bd6fb8ad3bbf9967ce031434ed2647eacac803aa0473dc2bd1f2b8a426347ce0564e45f5ab64b9b06783869e6a5b558ff1507ab292a207d8a9fec694a4ada1076319a890beda4b86261f4518ea26f5a13f89106244503997c4ab680bbf9a08124c78faa12f87f9b8608c819a417e263b7ae55db5f432d39d5b1161dc70b063db8b45486df862a7a4c5672a10761f1eddc376aa8fd35102e1ce0bff1b2c5219a5ea56256ec5aca2fdf5b6fa93c9935be717e36dcdb1d3cc3ee0cc354e7ed8c2da45fb0c2da29560a62d2d906f9b8eddc942f8f1d0ebb9d13efcc1d63af9044503c9773205e4f1f2feefa10281a26c7d0b7c94520530cdde09b865bf2e6dceb1c5780d0d99ce148c065e0581ecc1648b8ae0e744b5e5fa4fc32f915c669b3373b9fd7b1e9c26f9952b16139aefcb95f9b8483256beb06de231242fcffe0310f03c96e879789cbfe36e6507f351f32f55eea5fb70ff68b9a5c3fba3ef4f48f04b8e9611cbf855a93aeee0d537f8cba5b0977db110f962e0c3848ec3ef474fe79091e7907ea320ebe3d3ad06f4d093760cef8d310564d593e88456f5dc6c50383ccba3613260e1cb4adc00db15fe25b7b0ef47c6e28b654e48fabb914cf265d58f46b8d1a51ff072095eac1468ed7600c93a26e2120b439f492a28a04f48a81aedf84342af7adcd7f17a781b58de7b34a50fcc803866b26c52dac4e398f6f640f796666282ee5e0b64481b79692c417343320008dab8d5e72e10876f646cff6b6a1cc0d58db646725a524f83eab5724c68ffce7a0aa0dd5120ee07206ee9c1e4270bcfa5c4a3618adf93932040162ff13e2392685bb07335f207cf570fd335330374da92ff0bfc06a8f92ff3980a3244eafd3675574975134fd615a4582ac732e17444f5db05098bcf16c8b5442cd753bc50fb320bdba720df04346a44120acc35884ff5723e7f82f94209055b2b8ff0c69ae6638e0f6e69b3276d0d7d63ea2a3490c2b3ffb1130c0819416a08a1f55b3bac06bd19a97a519b3604f5110d494df4bfe85ff92748ef94acfa465e177f692cec2b93e5fa957411eb2921bc3ac65534b7641986bae7becad98f902bf0c059a9ee618094b7875ca01e863d7e33ff3d192a43dbbe7b36be2c9606668c039cdb6bfc94c3178d2d911297f1f44b0cc8575482cc98a6940a20ab4c0611c72f4d9cee91e50b610b1923c25a66da5e859785f42dd36fa78cbe26ef398e58aad8916bae3e17766003463b0d7cc08dfec5a421e82098c87e47ed82ac485aed74e8d3359a3ad7b1a247c3fd106e7b38a9d9c943c34e08a4ed82361b4b0af658a4a1aa30555868755f54f5df163f320d27c3f75b9f846db55a4a0b8192f5330deee5ee8bfa25fac665650853cef841f6a1415c80a005ad3e349b4878ac5c4e5688fc542d360b006e8305dc7540fb77cb27c635580508aa2865f2e9f4d0f00a997d20019efd06e8177cabc2a59b496978b9ff06796011b1604e3b56ee3ab77cd450d939bca2d19b51d41711c204b9635e60c3b80d505970bc8243dbf19f4805dbcc06ca504f7933f7001e61b1a867d039300e8d223b2575f73ded4979cceb05d8bd9ef5437f1c0802795135343c72226c258a4da077ea189986146f6931ff6742dd83ff85b4be363bc143a904184cd9eb54a5dce399beb2ba48984c72a0bd35632b8d0d6283b0f3050bba8a7e16cd73f564d606a39f35a9157618520bd4441392e319f1ec2707e865d75c6e1788369cb5ac6f9c0bff3b638d99266eac8d31cf1aed2419fbe52285ffbf0cd9172f0ebf8d964b72dedf3c6d94bf5a951dbf4e0263d073a6f4d6d934940671b29ed9a6abeefcafd2a01dfcba720fbbf5c6fbaf725d29454253715ba1730ede5c542817140531d421829e7c2095b68c7e50c1d9e8dad0962fb05cdbbcbe9322ef4225212d12d7bb4ef8eba58fcede027e4f83f797720910ef2925ce0c4d820f687f366955a19bbaace1e30c18b1f61b79b6463cd9343379a662cf3ead9581425069adef66bdd5825342ee86edaa630740911d02d232526dff2556baf6421eebfbcd10feaa0d3d8f9a3f24e143d4078c5ac2a608a069ac6d4fcbc264019945b9eeedd13118229bea4b7ece5b80732a0f207569fbe0655d95c88d4608f37529b57d1e0b25d09b95d11a6c99b5f362383687ef7d18255af4f44f6172e5daa9d9c7fd73b1e3725bca7452aefdebcde36270fe45770f3d6461c97090630f8bec509416d382a0cc3f92e5cfa56f6ec63b846d2ca545834ad4a677e21cc0bc24eb1d70643c9ce1bbba9295cd694e88e97944feedc192bcb2113c461470a36359e460ea9bcc71f55af1fb42d7f1dd42d8bc30897b768aa63b0c5dbdbcfbe7b0c565e2f064aa262cec630e3b7a8eef1df3268bc967ef58e1f08f9ac6b1c5cd051b2447405031524fcb45669bc8b7b82c4559e3188d63d5903275d40c104feb162502be755e7a6732e712e0133777c54faffef52cc1727ec9c33166f949dc6c283abc9dc7f9ec5f56ea660d75e06bb0de1552a891fc5847f2b2b15011cd684af0ae01974698a3f6849b6dd5f2786ee9df7669e8403d36a8d2c8b1ed257879719efb03daa17ecd0a0d427a694da22307d5b7e1b3c6bc2abb0ef0b9a48cbb0dba108675e81ed83eedf6f89b41d5d35ed66cc293784febac49ab708793d1341f88fa3d79ea55a3386b15a227d855cab4f454dfd627028795b66b77559efc2115cbe5eed8374490f5b690cd57e80b84155701ece7345dc2c77b34bd57632188cf848f0f4fa01eee513174025dd18c5bb6ff43d03e97a","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"5616fc32ad96bc6054a97b08493500e0"};

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
