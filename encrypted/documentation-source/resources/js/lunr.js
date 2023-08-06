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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"fb185e0f8a9842df3cc33eec1fd7f754f01e3e23cd85ee139977f1ad04ac04d0e42e823dc483e21841b29c5222c5024ad846b3184d5890c20a59bbdc173aca7248f00b485bd20527c26535fc5cbf8f04cac5f8225a8e6260512c7405a42a5bdaa0007eeb96283a60156b85ce3748c9a4d387d105533df05798ae1fdcb92cb1acf226699520d409554bf83b18aa78f2ff1c95f36f44118f24234233a50aef55e88176206fb9b4d80c447e46a1fd095052881165aef17e9efc8992a97659fcf7b2e18a6bad3449ffea7a3f7fbbe0f7d402e282e8c36fcef08dd644777334dfff751ec9b1b180522393e816a3cc90d4e7f03d73022abaff68ff838b75ca0eec3a4d22c5f5eb0871e409dece8af17f7ee3f2c2e721ba848d649fea77ac22a85cd8243fc4d1f69fdad78e51284b1eaba2c8eff7ff413796d6082be994a2be00ee963984f94a11de6474795624878b2f91c71edb0df0b11cfff70aa47945a005a63d00bc769a695b143bc748ab166c6ced72fd44d744595ccc13b9f87c95e97cde5a9fb15ef0681d0dce421ee86f0dc33e3f51f92c8765457f816f1f44f4bea11faf1a1b007f7746f1bad602cc2505d1adab74255045b45ea0f1a03222f3c5c5983457910d8c4466dc991b8176182a2a52ab7cc81148d29c60ca299a77f1d37824c87cf89009b9d3ac0b6d737a5b5fe29646a31b0420af4f03066281537d9a3cb2a0a019ccff42c05d58d50cb6d1a2c9cf4bf8abab9d645c987e614e5b77eb1579018da86e115d23ddcc1cab8d26e2c3dfc02960975e1df1d1a185d5865628a03279839b5887c36dad69bb93f96a93b0a9f13cb7fc0d8dd0f25a1b150a138f6ff29e015cfa0934b368a5390d4ccde8a136060f9807483923b63ec379942383b616264c7ecb670cf3fe0b2b80b44c96d687ce7383fcdbc85ef5feb850c0e2890154bc2433814955135e0969ec4ec5c99490c4e10234bb2e29ac80b3e3d0d4a7d18124132704ee3cc1046cc20cbc6b77e428192da03a08db220687cd93f22962d6e9015388ae6cd7e0bc4e8efd1fca75bbccb071d844a05ec83aba14b1e9595f9093f115507773491f2d39c319f4675f6f71767be82db004e270013a76ea718e9e91cd52272f775eef1d34f776a5c8e452c489629dbfd1d7bb69e7b76b451cd7a4171695a92ac39d56e9c89fad8ae9a9db07b41de12a723eb63fcd23d4eb7b31545ca4849ed53135357783c55ed5f0736da79dc37ee3eac56a62925c09e132375cdce85ad98749573d49b2e058ba7b3714d52be8fd846b896ed4a25ce5591baff73cf62c14ad4307a5a8b862059c52baee521a977594748c29deacfc864750cc4a65c94baaba0848dfaf1a1fdab56b6f1a5b4c8d25270e132d87ff80534d44161aeb563abb7189d789baccb900cddc810b8991de2d8eaf269906a5bbeea262bcc600af37c39ff72d21cba45dc29a649e041ea2847385a87766c90294f03c8fdc8b838e9d8266b678571c134c217f99118637f0ca79a88282b677171ad711e2bf80719e9aeb21dfe630cb006cdd6732da9b37c3cb84b9e7c83ef8737ca29c39d03c09daea6e77b319eaaf945555150ac1b088e68beef2757765e994a1f0a061618ebbb005dab384ae6eae57776d05b69e1fdf76ce9838648fa2c61b42f2db6f3c7d24d569a83df437be828cef17568db38323ee55f63c4f17fad22da99407f49b702e08b1886bea6af590d1c77fafe7e7f8fafa32ccbd52f624fc5a164fcd37062e33163513a29458a227d188febd98cadd79ce450475bb85a7b4a1b536c1200619e3d7fa5c74106fe8971ecb696de2417b604ee172e2b069fab18e852e9fe2cdf2cb268ee32834efdf1a6275d8adb3ad4ec75b484d0be83970598af90ae037b956a8459f88b335f0fcba70249eee3c2769ba46f4f344617078de157026146e8236b34ad915925f391d87b29ca2c714eb1ba9c96c897fa305f108563c8db520e79958ac4afba373fb919c38f5d0a14281d5739cd5f53bb6e27306dbc347aa865ee9fe73831efb28272468b8f2fa9f99848cd24608df9c8899dccad156c45f2d1a4db7a2ee2fd28cb07372c66ac4316f6d4ca0d101037e89ea23b030a65bd38b3931dd961908809f7a021eb8ab60d36dec3a9a5a2c68a883a3a7f5f21a9af7a2deea6126bf3a040c8ca87017f754e4fab45f30dc3416ca6e24527a9dbd81ba274cd8923ec8bdd472c4ea8a7bc7841af94b97621446e311e7df047e3bc6cf955182fd3602692d291399b5a4a43c9fc791eca98ecbf16ef3e0c161dbc6905d176e10d9360166ddf109eaeb8c279ee053919b2c557aaffc64d849ef87ff89207989e0399340cb2a6f691a87ac17d131aed453cc2978970305f929e53ab9652933d803ab6c26ab7ee78298598fbb7037d95dfa8318ac6e9e42315a8a2f9cbd6987780271877cd3f65ab8fe2680c7e658bf5e517c3aec0d7dba69a30013c4d5bb7775cbaaacc819828e0042872e0169438d16c2705dc1d23f938286dbe58d990e908d1454607472cedc3b7e438c33c714dfab8cb688333a933f2b4f842ed2f072a4efdd778c36c3c8eba7b17c72e193212448eaa49923ee68f418102b4895c5400d5aeefcd3f7e767d69e21ab3fb244d09834451ad2d344d1d42366a0b1c38628e35d88460abf4e3a5d0723d75a012d808f393b08f9a33adaa65cf49daa6e2ddbaf61532cb854067095629376ed022110aafbba7ac6654f705566886564dc682878ff1c5b022517173ea968bd58c7505b24b2262e85cecc700655a3f9d4abf712ac4cd224eac13dbe00479b365437eb05253620d20bab6605da68734f269775ff7fa34c833d3cc1bdaddc685d59af1d08b1a47b4598f53060632c3ed8f574b4a841efd295e19cfd7f06ad2d4e4bfdab58aa85be6ac383052bfaa8a278d6bf5f3c865464a4cccfe3b7895fd3970dcff2ace4abc0c349bbb79c38fc918fbb366be5504600fa16e9c2b097f13a11f0327d92499ca4e0eb1267a00ac22f86ea0bbdf4594b5f9ab9c9197e6ae451b0d44884f18bcbbcab9d336a4a68a7a217c80aa0d2349bbd69c0caebadaa8a084caf4a6186dd296ec808a679cce9fa9d591e1a495d16846b3ca0c16cdd1cf4dc0fd140f6b805a6d7cd34afe569b71560d38269057f22d2e148bc49042f1d3a6af790e67943790e16c228f2b82ddbc1aac3713be82b2748eec28bf46706b5269889f63bce9dbef9e6e0c77061a607660c605a50a471aa01cd46bbe3b1f818fd3cb8696b32ecd103f84fd4ac919e416cb118022d901ee4f8df88abf899545de45e4fc91bf1d661109867db54b4c12e9d21eaf4b04d42d0d2dbadb70016a3d1141997954f5ac21ef910ebe9f271204790738632cd53fdada5e82a48b2f94983c500b20223cd2c18c77d2b56aeec4c50c5cfb1dcb9d5149f90ae325176c1be9c3cba752b5a9773eddecdfd3930bfe53da3b8b3d8c71cb34f418a277a03303877d51d00f9f6e4560a59639b5d5685c5000f7360879ee752d8973514cc8b06636acf22dfd8010f36f9319eb94ecca9a08df60fdfc69563c68366a634d73d644c9f68518ae104496f29e56a32f259ea9e8f411fddf46d9569a5e9a39aaee1ba900065324e0947fae1654cf61ba3a53ae6297a463991c37496487425e78a6b33b84c4a853ae376f001c7727dca8143c0f846b261590ffaf9ef6bf16b0ebc556176370cac1dcad12de2e278bb72caea8db94553bcd374c294263ffe5f030506705b1c5654f9ada2c62caa212dfd64788d9e00ecf80f5b3227841cd8aef2bc18a7da8419cd5bb3a8f153cd248b0151cdcbedbff7d4282c2f70f27fc86a4be10cf7ba068ab12f260f56a4585d73875786501004a04f92a1a7ab9fb7a804c71c4f24fb12c13a933dbefca674e032cce40f5a6a83a0354d0dd49f97a2d02927817961e314f2f7f29bb47427ae6161f0117afad70bc6494ff2fccd4e24d5f95c1bd495bfdc0b2f43771a73661dfcbb1358fec06406d83cb51698888d77a2c4a4004a82b7d42a74097d093bd3143e934c8fd7645d9abbaa2013a8a38032e8b67e5711dba2435e08e85e559a328ae2e72a7929c08e326cec42fb468b140fb6ac2da40c1ae98a3d653a8e9ebb75fd4b79519e5fdb33e9a435f7c884b8423f38c8f4a0d6368bf8e71efbf33717e5577f24c6ec1f60c89bde18ce6853137b526f17ab9deac64f719ddf52f064dc1a16618aeab489b3f815a8dd7b47fccd76ddd278ac2ae280e3835f623e2b6cc51ac997784e0c67676d748d1dcbf4b0f0f1d82086078326835c0d262bbaf97bc63f14b36b8281351382391883d8e539679ebbfa878d8bfdcba3c896621cd458d156b37f3b79d58f6c9fd7c38e83926e2f3925791c8ec6836dff3e431cf677a50a286cebd13c4fd2309e410d44f58339531b0e1fee485ece2d186fbb21ddc7777e37851af1b324f24f4422b421bd0b45a27b9a81d25f8020dd8fa6a7a71fcdccc53185ba28900fb92d39e092062850d332a2c75cdcf4f0236e0ac72ffc04f5b77d1ec2041c1431e6b5bd803684cb58f3bbb80dee4f40d9839d4251478638ca4cfd4aba7993adeb5dadb7b9b997d1126aa11723a15f73483944b3a8ae2c217907e6f39b4144892cf026de0282543293d4323be2de42766030bd40176eef93edd650532a035df1a5c7a34d0881d85d585f233711a4c0f43f145fa413741350f6f811f4428051eacd73a476624dd0e9051504fcca4355c049e7c49e1927755568a19d9f66084d5c079bcac1866178d0325b6c555df8103505475235d9e714b42b221d12d2b447e47785aa59ef6f860982e6c74e5188b66aa68f619e808fc671dbd42f079094b103aa8a3ce008075de78f4db056083147bfb8d5592d4f35c2e9887a665a2003f3d482acd308aca0f95277d845d40a0758d7135056413b3340618a9a9bce5a1ede60e13eecd1c0a48b6aa5a24fe69873fbd1b36d169ff9c6f51ee16cee80b822c0afeed445327e204eacd0440e8808a189e98f0e32a1f6f773e603cb83bf978bb412710911e9b93a5abbd9b4e242ad56692a46323d92fb80633ec4375106c18740f6e6cca674451effae03e6db8d79519e26e6736763b643dc617db5e55de4cdf72662e60f15818b67cefc539beb9b859912aaaf5f1c6acf50eadc26184a28ebbd13ed94a8077e41c224cac0b28239546f8597401561b56b6bed64a49983a63f0cf23f0345b532884b11c7e1594a86bb4cf3f400f9b24d6a2db7a5fcc6463c0662e462691d00a2da4afe31378deaa5e92cfa0c9ed5ee732614db8e9b39a5691bbd697c302c145d8b089f780eaa601353cec4751e7388d9d504c7b53a5dcfef20711cdc14ef7df1876514ee03e743bc2713c6d01c21369c6130596be3957627cf08da6003077a7448fa5f73e38471dc17f03c414742011b76082828330d2de924e201525bbe3d515e6ab0f5f9db608b18402632f8e94a77a2379d104d2862bd42db8d4e670ac2417574b571e1c2822f0140a15e3052b25b5469858a1a6a5fb3604b4b1797fb213cc696f4abff154edc7680fba74f63eebf6a10b845a05c2eb0c55f986be694acb29022b164aa5e992b46bb917a1064f573b3cfb8ad7ec95e0f68798cae3566cd44c24338b28b33cf31cfa997364ae56a82aa9e4016ea0bfb2d3a7ad2d38ba555aabef511480ba9663e0c1d62781887800ff113413952b13bf200d5c01ef9608fdacbbfcf41218d9a93a9eb27002f1a8f4ecfa1c51c61ffc42c1570db572615f64446896bfb3c21c9c3fe8d6a73019ec098552358930a789c2f9955ca34ce161435a29f8eed5523359b17dd0fae43566ceac988d7e7217750eea5e54382c62b9f2bdb28ec45cfc29ab47761cee1b8e3ca3291dd1106e1550c41bb25d5ca75b4aa576af686857f8ae8d6b257e457ab0e3cbfc16eeaa655e302d63fbff37bf67241f593d2bc107007a81326d3e4f93fbcd4dccdb754ec23a6650096759fcac368a4e357ecdd69c83c64005dd6681a1b09a1c1eefdc784c9b71321ecf01295cae07819fd11a49d5f70466f14667bae05e7a9c4f38824725c1f1243ec62c5b4ac53eadb69c5125574e61888826d93318bc221ce25c3f7b2d425fb18ff52430a5acf25227c9d0d9f018e52676dbbf0f7a379633deeff24854a456064373364fee278e37b7ee9d5d9507fbe8387481805371d41cbefb6c36d90a5fb5f82e3cb33efb3c60bd0fd668511a04fa10a0b0abe9c1da686c162b10c4403a97189a68d41c30f87dbce5e0881648eae1130d510923bc46d8dfa764ff2a9ebfa2f96bbd34141d322a6404276d1998b04a722c1bd71f0db271a16309f03642f3f3024fe6014e27d9996e45116713138be49f2a687e73d08f053c84dbb0ed911909c09b7a1783dda546d43cb8fec0a143c33bea04f3ac7e18f1354dfa54cc0682333789f33c2844fe17309b1c34a0667d851460a72583cffa433ba758cbf53150b03b1b4fb732bcb9d0579673fb2cac71f4fab20869a5fc45b488d1f519b32e48711eed591d6d89fb2e9a2eba438846ea4e2c964519cc5a1a220db2882ec945e1635c3a2a951abc8ccd4a54e49c09e26918d7713701e9c3dbe066b17b9a7fcb3fc2afbcbf9c35fd3984d807d4a4589729901a2b5286e4a64a270291abe948ba3dc6149a8d5f05b1406b7f23a285b7a1f3c4a0375578522b16e3d27426d93ec14591cc34a01f5f03b4cb2ced0db392ab9ec11ef5583354a409cc17589d4c20dd520a5e938f2f44bf2d084b8c244758379c9f94e2cb9b73f6d31a9684c1a853d1f3b499ad24bef88ab53db406bafcc045122a08841b84657c6ab9c13fab9bd18d8ba093e1f4f19eb42af1ad8c4ea2fea37a1c0a7e771acbd317cdbe4c9d8d501f858edcaccaba384309bd82a77544894704eb7d54fcd53715701251f7cf386af3c04e99852e06d6722a9bbba153c8cde3eaa5edb3b18d98df9dabb36e429d06012563fe4972e4277a4694e291fe724b8d0b7e59519d24474d542b11211aedb6cf350ad05bb97f3e911e69d8bb4259f1acad9ac0cccde0342b7025249fcdb1fda64224b23c7da46aad28d603a46511eb31400c38e24b0a50a71a9be2a6c840d0963f7eaf265e907a2a4093ced6aab1dbfba201e7fdf5669881d88d2a2dc89366655690762875979b2edcfc66d665475d74141413b7d6cc1b491301168b4e545e286561854e97270f069b985c7624ac3fe38edd86c093e2bc224d5652233a97cdb12846fa622957d977e79de1a00888ec786adb10cf2928fbbaf8fb2ac94901a7986f37358f51453f0341fc5f40d17ab3370d64cf0bf18c5e529a2b6bd19bcaeee7fbea9948d85b66ec2ac831026131e5a0a1bb87a35c3346662e9bbce9d5bf35765385bc568427096db02c1af12adb1bba21af626ec8c056b3f21df3f6685396d525b7c147f7b5dbbf2724f01e17a88c04f602a58c8848ad77027e0d28d779ee614f73babdec279767554158f30254ffa181de6eb1519cdd023d44f12da15e9f5e9c0baf8493c673ad004babe5cfb7adbeb49721571f139f02ad01ce3e384e480789c861805e2228beb255c07dfa4493bee62303ac1c1a1ea099763f29edb73f210543b0d20f659051c5af780d06d9f706a537084f16aba04fd7e3a4e2e65c87997cf8855d19a761dea7774b4b96b6c6369895cfbc4483b77aabedc361171f43cee8281b60fbb9f1c114c54608ebd6e2d3ba817ae96827c5e52d913d81de09b2fa566b31ebba4f2bd5a5c901e3d5f3289140942fa5f3467a6b44ecdf84694a2232fa41f6a5f472819baaaad72a46bc26e7cdde3b18b9863eeaaea79533a16b974df299aaf6c026ee9b3f95aa7bcfb902a7fa2dda7bf608fb2b8f163c9f6c36eba9bbf179dc76698819f06602b2bacff1aa6336b029e0b984afe250bed995291ce16092ec18099fc9dc7d5da91606deb5f5039a1dd23e034ae4e145de8fec1ebacfe4bea298b0f90479b03d97ad4cc4f91282559411e7675948b31df4699cadfe4a93048e26bfdb36663036034b784fd7dde64c87b8c522559a610521155b0c6f45c02770c5b5d8264101c8c48352854b7737869da6588bbba3fc7570bf7def92433f1b2cc16abc38b022c474c38b32ac068204518499b2c8af4d395fefabbe54865dcebf1adbd6d78fe37dcac21c4f21424f1971f9a77fa3128df13d6ef0049d458d7ea556e10c19314a8ad91845effd26d6feea6e41c5f2d4c239698b512a000515ccd094b4d2aeaa74248e48515373a8ec35feb1fdb284c7f55f2bfe6ace9fd717c55ea2837744a113f3f59dba1574598deaa2b8ed131a4c7b7f3e2abedb0d62f0b860183029279d6e9f5dd13b2275f5b6b18cccd4658f7a1656aab29dcd575ff56f23a1c25be0f49ef0b94926395d24a340087be068026f4fc68bc6f301b7d1cae4c4a35cac04d87169851827eca14fe7e64f559e9338b29ddcfcf2f446d5cb3a9d596f51858c8c83fd059b233fd34bdbca43a46c82c379af19052abd6c7f7f59fc2ed7b2e089d884c977002e8f6ce7d0abadf2186a2903e66426baf8cf941a9a59cd2a6e083246778009b1f04d03f969d5bcac68cc01a5b006e08f6d234798c7978c84b01efa682af0dc4b794115e77257b001f9ab6f02a7b3c767f38729b3db62a19c4ca9064afba14bb0df675cfd367e58ad2166195d780af56a930fdd05f1e8c3e323ae7536d33fac6710407e360a744db9634642cec958d29512922c756cfea64af0c2cf3af1c2e32263586c103d29f7c6376e1aca10ec81fdfb7bf4b4f8125241d581b1471d6507366719d0227bccb87e5566acc03bb2d61fbb8ba70448501f8a4ea2f2590e12f88d7bf99d3c9edc6d46d4065af0cf09aac7a882474a9da7ccc65f8ea2e53ebd770809861f37d36be696c68c5099926a108fa7dc2a2e8074e7ef3326b36ebe418fc637a682fb1c11cc5e777bdacfd6f917292283a4b54fdf7f3079b8d3d031d2458c60f9bbd7fac53fcd6e0ca69accff8e8055c9aea574917e17f262cd1246eab179a6346a47c4b24f1f580ea36245d028e7681acd558dd67fcdddbad467624f47f57f5d128422450bdc577cc409393aa528791cbe36a4a42109077606dd601a7b8ece3ab73dff07af52a02ad6b7ac7eabe449cfd6589e46ce8a81e11c20bb30d1148cf4e18f897fc91a4ed7c9b64f2dd74873b08a8b81091360bebf7b079fa2dd41831373dec870d721b4f50916160bae102d18c975144bab28d1e75b9c7056864d6714c96a232a99b173d30a5346b98c71d0ea26aaf8f17ddc1f89eb6bfac4b2d4ae5b2d706a764d4772768957cd9759dda7061da39c052e4c44c004ad322051219cc133e13eaeafcecfcd7d6ec90d22a6b551de2e09945f68918b37612418b3131b5c4a1b4785a2976fffad935a8d9d198daed57afa6085cc09d8d4c06e74af7857aba415e461905392c4a4106c4c7cbc220a05663039b031a12844c6213e808c1e581555bf7a671db1ccbdd51b717bf8538a37a0fa7315a5f35085e983b637f411bf02924383da13028840f3ab2ac28a14791be9837674492d1c6e7ccad023406b2d7a5dbb71cfcd8f58100ca3ab693a74ef6221c732e09b22026b296d2e35c6afc948a3bb162cf9b35a96d0dc2cf0f393fb9f40638d30623c12aff9688bfc4a9b4539c26b9158c69c14886b1fe012b1b7048294fc5c8e5fdbfc81f2aca921b0473d105453771f99074178046295b9ee7e63e2019750cfa583064016513c7e2d91dc560bcc76bca5264e5e90f99e904c394edb2afa619fff17fb3e89093676eba1b1faa01aa81a5decc41b0eee317cef75a8feba0a7c3ff63642896a3e0ac752a87ef8d4d73f31cfdfa6f4b9a5856527779c8586c55ac252cb4e910d3b396008fb26b77d225593c870b845146265229294a284e734493d994d09ba579fa2f5ba81f43781ba0540bc6f963ae1c2e580bd5757cdc9372dadf12369fd61cac195d1a898ab49637ed7e43edf8f5675c6d8bedca8884335972f9a268495677724d8648ea40308891ce374d6bc3ad63fc53e68f40b8a3a7bfc98ffd68dfd8dad7d35bfd652e84e4be139ef546f79f63193da9ffee7a8d76fe064f184607b4034d90deb7a9568c4e8608ef2a0d093a08ddc8e5daa113bfbb13d829b1e28071f88ae0dc3ab230b9c85ce067ae92d2738640f523a313ada1231f379096b3c9505d1766ee99eeffa1f7ecd6dc938a9f3b9955820dfaaf6d2166a77cbb2e901349b622c7297fe3c0f2cc6a1df38c3e73b6c20d40e9d4fb21b48e988bd7f8e16c033c071efb63a28c7eb8b66749bce4708931151d0cd243e3974ae14579eb41e5ad4fe0722e2b61c3e9d2d6cba1a8ee749202681c36cf2e2bdcb717ffe367cdb67446d5c030d740388c27475c09581d38fad2ce691946d6113c33ceb75c48ea963d67f459e405ae07982d241d97d0f8060838b8d5470b294346ba65fde3da7d5cdea7d27d290eece193936b16f48435c0dfe0367bc31590b5dccd46acc36388274a77873c09acb5fa2e31dfa57e07f970b88bdac95cd36c555c4c9c7386bbb8a8e29e89b7dc5894fbdb694d4e48c0bc4ab2331ef62bd399e2e949e56fe54da8d8bad9f0941ede174ca0916f303ecb9f29cab31b4ce91c80221b0c25f3a3bf7406e36d9bf5af8628b84bbc0ff93f951f9e53c7b1fe856182f5caa6e594b458770f0dc62872c821bee9b556347eeb1afbb623df2c068386392cd38836218a26fc37109f8c261d1e1bd73457bce411048a99163ff3be69923fb49b597adba4cd24c83133afef7a4415573252eb3f787f3d78ad6ccc8baacdc7205bf26679c42e32334a23c66bf98ef614598149bc4ef2b819f9606d3c060fe34370af2e93192a68a4c91155ed564dc861b6f642a8006eddad51661284a42ff991db41219cae5c1cfc8c87047a1e4c899e6ec00a9bf56f3bb72a720a694f2cf3346529d66865e40deff2029aead1ee9fda0a0e91ada25df4302253831c963abf34837c360865290edc6700e9aa662206fd8d541ac5d25ab4a671015b00ac62aca1881e0f8eaf865b3f692dfd1342dcb8bac43195c4e72d1e3e884aaf3f06bc7434065f6821c8e25d2b54aebdadbc0b595a94156247feb5c5c2df87c8ca1be1424385704835a63abec1a0d4741008410b667789987b785869acdd7b07c7c9f20e7219ff77de20a332a3fff1d2f4e35751e9ebed383d0b1dc631defa46d1f60a294498cf61147c7ad5f0e742f84682276f74c367b4385e402319a67ca5f845df074a04ca693b8ff37f258ae0003cb6f211e45e13a5a7fb16310f82cd67ccaaf77e0a2dde4bd2577ffb217e5328a79c9274c12e2024c429eefd5b5968fd9b227f939b7c8983e19027742385a056cfe95a79425dc99d6571806666a01fd79a3ff42e01813cf2b89af81ec5bd0bc924c22d2ca7771c09333b64bd3cd097d77ef465c665f089b2c938b330aeea335746ef5468504cc698d25ccfcc0d26a34fbdbb720794b5fb10a27519b34c8b50a78a07a90c6ce18386b30691cb62e146ce9bc218360401bb8c96ad7171926367ab77af8508e629dae92d1bf7d02a7aab00f29b6cb4ca16623e8cbef7a805a8b0cf9fd781262b5cc96e18f3860f0482d618dac47e2458d7c400ecd83f1f621d028f578b8356edb31fd320188452508fb3bc47096049b7941ab56f536957469afa57db87e273a873ec5725d3129929bb0ad6ab369f21b8f07c45832ae9cb20a5f9490699f579f1da4aaf2b551d5275d12384052e30217880d0d0169035d987cc81040f56dc3cdeee8c02e9875e3f545696b8890fc488ce4d71f8322f222303c9d977f829d06b0df91195ec0e48fae81d0f0fb5bd20afb13e0a4ce2477d0f8d9a78382ec7b0e588930b40ff57f32b755aff16641f062450e9bdaeed850613e9fd4b4863d4558c89b2a8e6320b1f5f1ac7bbe10b9e421dd24960acf95dcdab3781d7593ccc99bf38797a24dffa8a8d66a6e52e936ee0ecd33ca9f832f5af1cc18ebc804d6f463a658efcc6d867dcdf66d367dd009c8e72ebc8e51cb238a3bbb2201a61b5e44c68dca9cf44bf453916370d9d9ca168e0890f7de8d24a70334c70a6f92afe1f15580cba210b5bb2c106611d2fba3d65444b93340ef93e44e8ecd3edd447dddf079c168c2cc630316615b2b4002b55b5b7810fe1d6177915ac473bd46081cddbfdc66b494fb899dbd5e5463bc7549b55a96d69ba2f0153f43ce63d4d619d0dbfb727af14aec4e8937d353b627320418c1b27be9fdab3214df0c1d35aab1046e043829745324ce529d7e651bfe26fc641f695869f25ad65fdebc3b8dd368d718c2c5b47bb29018b106a7738b066e938bfeed53329be860888e1d933c84ae38b5101927c5bf1f0649caa513e7c6b76fadb8bf634e4d1534008f4eb6d9f5e576bf5b3e20f161c75bf56b08fe9f58ce5b448da4c77fa69c1a16f9daf4bbcd13521714f3a4941159889f0a28f01ea521ed5ad606f699167e07791fda12518cfa82555387728ad17a322030d81e9a6ae0f729bf8a977984dcbd9f9648fb071d2e965d6f484ec79a4d5470a547a57fc9f09d570db4d06ef493cf5f0f18b4ab510839d5178f7264945051b82fb9a229aa1fb672ecb55af8620eb7dd58e2187d580ffa035212d38c1740ac0785c53afe856021bb83eec5c12f0784e347d5c0dbc80f2d4df4ef8a124cec7b663ae4363ed4b25af9308a769220965348119242ecfae68586d0c568625fd98d12e96e07599f12d64e018d0bcfa2627f15361cb93367d4e2fb941ddf198b106cdf0f7e1e1ac360c70b99a91eef0e6d2571c0af9a7b6694e6c07584ebd55d58dd9b09f3a757f7b28625f7ff7a341f16896a3254342914467ee06cbd7358418cec441b0540f170bade291f23776ac10140e901898c4fda2a0d28a975989287d0500f4c3d9a7a3a6a015e329180964e99b5831bcf9374e018c4d5762db81c8fb031b161ef417b2c52914b1e4873c3955d0b5096ab6774f9840dfd78a6251997477fa8b51791adb9f424525b3a7073898068c3b2eef7eca936edcf1ad65f99c11431d37a1031f1b96132e4af4ca367a72571f41c606e2b7547c98384ce0a5a8cca4a34b756d9c0f23e72adabc73ae6a3c4829370ba651582667dd96bd6241301fd30c65dd8db17194bb9df5a7ee99872eedd595dda777b124c050bc75914acb88ccaf28f03962e9ba0c768ab674bfe5ab8bc190657941215581b50521bfe6ef4d44859c78c04b70fb38e41bf0c94bfff6bdbe440eb9f5ec719d6096204d6ac8c049502e75bc656926a972059028997cbe6996ec15d7d2613846d2df2458db0954277962fc099b91f4f19c2b70b4a53e54450b5c9a97759fd01bdba55e19275b21972b45d7623ed59d72bc0fa9b93b4bbbeb94006405d4fb4ce4916326f532546fdc5d1698561392f2f3ec4c893eb75cb78781d2f7e5bd0bc805ae16021cfebe755c6e44aa0af7ceed221399e780dc7565f14f36160e97c40e5fa8a941603ad538b53511965c2f11c14168124eed52c9cf481e499cf0b65fa8839be5514242471c716429d83b2f1ab7106687ef34b1556b79fe681d4b1f7e045f76e9b28bbcadca9a466049197d2b56c8ff863c4bb42cfce538e740cc18d0ddb88f185e672aed29759ed06d926abc473788484a5ad18e42133f7406592627382870672c19f9afe84b8793620d59f833b016ddefd377d333793939ff664307d70681135c8232990ed2c0d38f3fd97eaa22d6a484bb4fb64a536e9a3cad0ccf98024312986284eef76a2ca8404e336a2c0430af31c63fba71f923722c663a97d74fe3753d84f1cd73a2b89d7ea9d3ea3328eca90fbc484cd98090141ae9492ad0f55ff8ff33cc3abfcbcd4332afe3a8e69ce41e5bd3d75d3b3c36468efeab6722894285fd1dcc45052b43ce2c29374d253ccb1a4d5f135ca15c1571d321dfe23eb896fcce7f71e9eaef6ba336e24ed0c76089b328b798b62fa0ad4ad3f0735bcabdcc95e32446378e556d03e2d589f88efc1b53f86a155c7845c3c5a7af0375c5f9118a3973dbeeae3edb2d1b47fa8f7a10aa6fb860e95a7c0ece9abe691084c8942b576bae6ab34623ed008f54538c52dae8ae224f48a9c662f4c5b736c780ad256f002c9531c39d32674d2816984a51859fd93d1b34292d3a84a16565e93048dd29da59b13dc93d1a93bac30c66bcc741bf5aa995439c622307a663e53070ddc0c3065fd307e2e723e56ac95319f6702ab81d8d30458caa5f2b9d2aec52d4da790f9a7b87690765e0e5037f3490bb519ccf472ecb96d9f0f08bc38384681cd13403ef0611d22d72738fec0faaef81db66fd4dbecf0b3fb9ecf30fbc15a2fabbe79de6b14f57b1115fae8560bd47374fa0499d6e179f31cf9c1a8a0b1767a1196c67c574df25eb6cbeaf9603a75c72d57b2209a56e7cf36b85121c30f19936bbdd7a4a252371bddf1fa7894ec0eccfed22da145dba2bd176412cd7db0731c77a825f173c84348f8b31a6cafd34727addcc04fce8cf52de090ba1047692f2702204684f67bba770f0bd54a65197218140bf54a44be9c25f63ad6d17ab7fa0eb00063cc9489921c89215ee38fb44e6c9357f580c28e4169ffc8561d6c31df74414dc0bf0ab16989ad25ebbfbe2e0e807495b126f823f64771ea6ca226957f2e2dd72263fd95a449f2e2cb80672b53c74acdc8db9549832b951ddd3a47287ef98753905ba1fc1827774c1f7cd851f86be963932a82759a1e18f24f933f6caed525ae6377b5332fe485462e0241adf12c6bfb3b3bba05e8a9543241b48e0d907283453e79bd4f56d4f7b7a748f2e77822e4b342f46165db96deee393fb49974b75bf61d7ad3049536221940dd7bb9e851450be721a00150413a4bbd67045052399784c36c8863b4ea6745e8a4fbc310d8116f1ca16e95b1e32e44ce5738795f75fbbd7df27cc24ca8be3e350af98788735cdcf77aca46676be31033154af0f1df1e9af7e32f010f48fad6b80eaeca28ef799836c70ed351d20eda67a1c238d93425bef3898d06013647d6e1eeda24f4d2bcca69c73ca72cccf385a3207574d2588607c20e402f325b05785f4f7d21b3e5b390107bdbcef05efc360fa3aabd9af7cf61c341b8a622d9cfe61f7739539dbc651b4a96daf189a86b7489a9a157bb3fa560a47276b985bd9555ab3c83a4e053e2c406382834e3a40ba74627dddb224b98fcd7307aadc996f81668c09a2771bc6c31b7be034f55f9e7c06201bd455683c05e2f89a6e7a8cb1cded4d43bdc1ac1423562c0543531380ebb1920dc59fd6ecded14a9be686f33ec1b57782ccd527b251648d864957f1b76f2dcb7ec1c791fc53e768adf2a23512115e41d79de06ec9869c144bfcabc2a2d27fa9c6a2ba905c6886eb0df5263ef72e57ed9c9b8b2420c59b23926818d97a79f5d88e02d29a732ad30d33b2846063cfd3b0ba6e67a500d6e88435d214f3d13e5c60426ae676e614c9f8b7f67e48f68e66046176bf78d9d7dbc53d17d5f90527d3f1a0681fc2f7837301383117b81d705c1b958a524a3b6e7b13c216989e976362ce07f407e244fba953db4207b6d2a387d2fa4117383bd77621e4b87114728b7b25d600ca650504d9b45b396aaf02e31e027f0e0ccfef7ebfcd5f4bdf6a50b5dd2cf16b6c11fe5ef41f9f62339108080cfc1a68cabad9a5b6f42c69e9bb23eb89b138db80af756c7945ef3ac82e975f0bdccf6cb32c81f21365b4656eb9b963df681f8c1f77c49b93582f6a052582ba68fce3d4d2b4265ec5d5bd86358a9f01c70cb354dd4d3628e6dadaa4a1055bd318f83a1bde2350ba900b646e62d1b1121cde05a03846af10d6a209460d7a635102bb77370077d12b20eebe1ee846104e84d8c2ba978968f745ebaf0568eb8fa7a8cb7fd07f5ea17c68e777988e7e1fd14f1f2b474098b67df2f6e711b03857a1179ad99d42859859574e80d68eeaf8eec78dae5f1403adf1aca88dd2b779f9cd63856ff508df61b0e68daafb878b7c7382bcfa5184bcec92189024e7725a3ed0e155c9621b9dce8b0f4ac5a92f43d575d86cbb8d34f40076c8224314f4465ff677daec2843c5ee7339ba2c6e3c18a0a3814e5911186de4872b8feb9a0fc3731dc7fb909f8044ccd4c0a09cac28dfbe5b5aaf8d0817653b7cea2450224dafc08eaec6e43a324ccb014a994a749453dc7de295f8d53403a0d102d7f8b9dc66654be89b0111cfafb3c56316355635afbf9322913d2c1e823f10c33373da6e1ef94817974c3acfae85e86437790f002fdbb1e9af44c10b14182aa8c86e7a4151f1b9e785745512275eebc4dd15ad2726b87a275028ec665f98ba188231ef7ed56bb841777696ec34490adc3fee30214e0b9070ba7641551bae5436cad14e71c8ebc218fdba086d4e1ba8df06b1c476bf621df664ed2bade4a7286358d3adeed47ea371675e81722056be2d1a5272c738029b990d98265abd122a8fb16cdb2059b83ed679c9baeb35c9b61367afc4709495133efd79ffe62e783b5afcc5783e2810c516af5ca9c0fb68607aed592a16e55d588b5e690c80bd060061165fc5fd603d22696b9dc371f07ac915ae091dec7127afa2e3b8d85803c5ad7ed7542cd1a43bc80559e6da6a1941cb3c172a1d7679838284c354e1a2b2b39ac14e1a0904bd483bb9088eb4737310df09f00c4babf2c03719dd3895ed0b174b81eb6e2a9abee24bb4998738afb51c0473cb7c9133dc7113bef9f4d361bdfac3f9a9ee2ffe1a8b55485457897436f067b4861fa15d660e8c60dd127e68a3b0c95847c82e77d2a6b11a6d378ecbbb49a1ac2ad00ec1f14c2c2e3db44ca304909d0d104fa281d0f09b1dd49a9f397c24999132551528aabad284664d17bcd0af7d28cb866d5b365cac5a9bbd5316867b18e2a1645b02f4c02e80529fda56490847bb589b2fbef51f80be5c350552ca48a04055618a1f7c7c7910bdf8d453712abafb3b6fbe03e9e04c7ccc0a9fd5cd7e570cefd55cc7ff406d08a1f0f6b607539ec7b16ffe2c13608b166971688a6bb517bfc496f3ca76d2264381111dc6154a1f877302f391a5f8f96539c229863f423c73a3d706adb66fc7364bd4259add3c380adade935dcf7778267d7fb53fbae004a4fd46d31c48f39d74c550dee1c3a9c3cf6b3c69bd09042047c743e3756f281b7073f0dd5bf7de0cb466b11922ee3acd25743592c8a3f3500f79ea28d48d4d34bf9801c4f2ddca7c3075239cf6ef9cf1636b5f271c181905bb7cb47c39df3f6f16332016c4413ce22e0e5d5b58f45f20341519f8a4dd94a62075c12fb8b570c0575a703718e148ec0cc353a3120c3b7326bbe31a967cd2ca595b39aa2548acb72192b95523c226fc6c36ef7dc2175c4c53d5b286096c4e2c3efa86670bec567b933cf55219e3805152b6072cce65352aeed7fd2edeccfd36e89d02dafdcfbb76b9434b2df87f0b2d51f734a3eee6a3ca25f1807fb42ca3db9e3d730155bdbce2ffac6876b4ccfbb81f53cbfab6cc70283fd98bf961cd34873c39d823b5b7019afe5706726362a666558797de35c95e95d8597a8529c584e606ce040d88c08b604296fa52c4e4995043e6b19086744b1a344226e17408ab8fa108b30f381a2728e61c5d1b831da39ad8814c8d02e11e16f0953d13190a2baa00a3b9645d2666db316967a2cafec65c9a733681feb05c7173c5be1113efe557f9bde237bfd45fc9b5ac27a65d3e3b91318471c90c47b2b2a92856cb4ff65165f9727f80dc0fb34a57d5bafa89d47388d8bdb70db391cb7c5888187a5ba35e587f439b76ff3a7cb3325f83f6bbbd8f7a9d9f379257c1c1373e7e30b3a3518ba399e7c98cc1279123a2644c040e560b02f688c779de5c85da30c80afe89c7ac27a4a810ceb9bbe0eff133d70e97ca6f1cf148adcd8c8747b0ee31297e195482404ad97b10aec9460822796e739441ea2fe17aea9a99a679626dee9779a3c5983967c9447e0b80605b29ad931090ae0b1569fd5d397967a2e8fe09b21a3b225fcb4551518f67211d75bf1e40a996f43c85b4b340da3498b35319a76103c25b8831d67fa784aa0bb9d0be3305d14d74ea3468c365347c365cdc9325fa5d3229ab0157741414fe4099e16311dfdbaa2f5273eacccea0b9850a9cc8bb002a999cdc924001d634618276f4e545a6db09c55997450a2b1de0c79389d510bc4a24feb68dd898ead16be29e6af9d200ed3666b4093beb6b41e4bd2ab5328a8adbecc1cf75c1891a6d48bd1ffa5a4e839b07dbaf068c5468656b4e25e3be074f1ce3b6e4d30412f9d1a116eb6b40c738a4a9473a88457eca0475d1b76ac3dcb1e5851e29b6aa41c8246b2ce93a15ff37004077eb3062bc9605b0b809296bd82a648638b530608d909dbb6a8123b510635217b1383c6b7e8ea923d09d6b226c9601beffec163b540a47197ba4d804c4e0fdbda10b12852ef93b2b46ddfe16520ebcbfc3faa882511c89b727915352a408f7f5c7ba4f24d169906f5acdf2439857e1a744c076f260c4923158c02f7117107770e3419d3e7263929a540b1abbc5f378e69febec393ae47554c60815ab33f4537bd4a66afd5323b6244a111ee4d325b4e56dba990a39b9ef779dd37cfadd1b9284a84c4b375c82c3b07504ce594ea30d5fdb5810a257463b81f91d84d869d000ddaa47eb4ae50de12de468ee7b87873515a0cba521c317bd3e7428f15ed8af0f4ee3255e744a08a01af352a7a514d389ecca23e7ab77969ac60455f8c7b5fe33965e3dfc0d8028d98fed99c3cfdd545847ccbfc79a682bd97afb3cdac7a4e1659e99eb99106b26437759a06850c46d5eddded3a16b5b3d89393d657414c8a1c9c80c9b2fabfc65fd9558e9260dbd821945a9381c44002dd4a9a9907513ff147ac8b9dd1fb767c6a4ef995a264cad24915e787a7e248cef2933b31c39e6b9a749adca46397e03d311994d17a4428e59f4daa6adc6fe64c55b91dba5cf819e47256c16957e98b5b33d7aefefe80cb445e2c7f250e5972fee3c945b76e45bee73deb4b9b16ba616120f36b732ff993ad48c544c123e1b51617a29445f6889ce7bef8798fbc5838ac1be60d01962ac415aea869d0b7934ccc0ed9fa43c4949d880d0b8650d583401d6871748a021571a524f0760e38b025195a0d25da3e29fba16b14a601e8dfad6fa32ac8aa2d8426004ad37109ca4237f090099c3395902fb85341cce1239cf75f099f8ff76ff8498161b56aff5093ecd0bd5ea000fb360d31892c0bb7051316e1faf82fbb33232d34d3679634ceac5a43b453f2b8831de61a98a4673111f5631d481878baf641ffc12cc007aa4587966f4cdd9d083a4b3349097065fd58e543f9bdb83a50ef62159ef38d274d7640ceaa708c1f4db83903e63871af360a771a91ce01cf0f0806ec2c013569bd69f888fcf63440b975d390f829deafe80411840f04ceafc5b8b76a094f4ef783dd7c4b6208fd57823e98eaf2a25c89f05cf90937a9475c753533478e38922cc317cdab016c4e018a3ae8329dfd93605c6565dbe97880bc489bf6ac51a060be7e44603f0825b42c77fdb31c3afe9d0875d7e7e6fb513dbaa5985faab4318b7e9a552cb15106dbbaf251c5b5246d8b98ea67ab80293b750a384d065b0f0f73cfecd1af277b5c2d4d5149ec6d9178de3afe4b71d947ba4984eba28ef19324406e759a7cb496b5d625cc6099af30539cdbb8975c825b94e8014bc4763c2e8308f12e5a5363016be4af2f669ae55bec856147a82363be461da0b5d9b799b25066772e71b138f92a93497e37cba76544d75bc05ca69abfbbf81b34ed36069a5599aa4566030ccec436976242473b0ff8535162d3eb2428745327a188d51ef0d4caccb3c5f3c127800338c7621b3fd7820eb0fd46735bd73b3c1852741886f76cf83e1ca759b5353287691c55c8938413764b80b4f881cdba545d97b005f04fc6a7f6f0da8c92b3012080eee8491f4f57844ba3486dda408342899ed9aed3d83ec36e016fb96d96a36fe13087df1acfcfbb3e14b6b0025618ec838e1f873677cf0a3069f3f271bb6cc3f5c854bd3fed50d25f3faf915875ba4ed221e5824d099f0fe3e1be35aadf4483cef64a670f4418bd2f52b7b5f15b29a90d0c7cc9b96fa426f5f32647233b84c77d064ccc70205451d769f1d35c61dfd619e2435979eb7bd86e740536287713afee47f70b5f1444b17b9a0fdb14016e396e29c1e8d7e921a29dca5daf72dd3213d52a0c3e016b48724ebe208e77be1ce1d347c9e47e30220575ad99fef3d1d8f687268a48a140898a29a0f3b43bed849f2b212fa8eabe8d62b76ca0fab8c89793ec55a16e0e7bdde96ad3edd1728d302a149dc45995eec7331c30616fb2114f31bd20a76fcab1725bc7d538342d63db8b941edeb22198401c7a6349da1653d6e15dc8d4faac06ef92abf31d5ea8d0f6e2bed74e0686c8c67810f726be9119848c1bd8f5b991c4ad48c4eb488f19c00aba351eb46cbfda54a0cc44bca5f4c950ab7a81831f3a5c37d8fef8000ca30af1330d61d12ee40d7c91f366136a24623b3d09c2dba78af12942ad9624e49cc7160bdf63d47fed3eb8638bb0ee39ef953bd335e7dd38dbbd360830a6aae76932da77266c92aa10037953f0e5572154a7b86bdd63162e69bb1653e75599116b391dc3e61547149c3642bc78e3bc84e280302a79cb15c9d0207fd5109bae11c7a29ed725011b4b52b87a6a2d16b24ce0fcd70e1da716b0511d8de3bcaf9afcb218ab1e3a2403b6b2f3575edab325da28707770cb4a37594f916b2cbb47a0d2bb365acda261c71e19ca9e5807e1bea8dad6048220c4ac42687a9d3951379ed1140a43e878d4b21ed22df31eb3ee7363fa83b8ff1a4af47e4475d078c153f4ff6467fb82cfa7372c278520be244c21bc7ae03a63ee0bd815706507c31a5bcb4e349bf513e6e309942e7b172934f01c53929ef039f7fe33ff2879594670db3d6eaf54b503c100a75e3d07e607a028d1dc37d070153e68eab26b855238c3811e09c28def324cc1ae733997124bca954699ea45831667a76d19a08c095869d2087c266ec760a3a0ef7384e0d2e44e5e73c149a54dca9f3f6add0f003f0b20dbb9d30f8224d155435339ffd4508024b6baf2483ef3ef05b6af983dd4d4609798f9fb60d101d062aef30d81e1d2e2ce6627a4fcee3dc3b6891bf39c1bab7eec3b44bb77bf80bab4e6e6beb54f9ca5f39a5925dffd5441b08da9b070914850caa23407c6b9d6e0b3fe9da566792b1d408f73ff9e7cb682c82dabbff3b0c9c6bb108d5c8b9d706be2f881942eab4426db61dcb5edd0aa81841e6c670c746426ea6d1edceb0645c2131c48e59f8b8974fe2979b40d497310ba79148e0db4bcac57f09a93164598bb8e795ec66e3cfbe3c5b92aa8956368ec76ffb685a0f012a2c0ab81b63672a177387c3bb68623f1ed2c4b3a92cce7608a06c138169104bf6d3b5354ee864d31c27a13ec683bee459e5c3a04894c3164f516f1167b009c96940f231422f29db7159f73b9d9030385dc97a7afa8cd38c50e94667b506f3d29009d8aa7bb06d8f0d861455d997beb72dc3f903851d7f0720c316331a98affde3f2e4409469767822250b6f754c09270a84ce83e2a6b1c4732d722be3746601f1e041e5b53d4fe09458b4204365fc6f734b2d111a4602868e68da55fe9a718e953a924ce26a6a9cb867356ce390d562af4ff57994da2daed3bff80cd6d2bbf075357d2cca8c6d34d717b415e12453589ae47286ebaafdd5d1cb72e9cb483a2d10f0be75075932d3e8ce71118c6a0c77cd69de433d1c61b545de7a2c1bfda296b4f61fedfa5ac4b2ed2d67a18a01d854b529e3d0406f997372c212752835c57e257c02b9a0656f2a145e63e0d671f920f33f57800cec424bc9853adf678a78f7005c5ed58dd97524d36bede7c95100c56f3f30620e525019a3bdc8c3c63e7f3781e87237760b55331bc1f02f28ffc6e7c00bdef467b3e2287366c498fcc1b2690ad49d91ae96204e9177800b2e680198bd578425f83eeef49c444ad1089f6ec0a7eef44e257aea2f39c017540d3144f762ad193406054dc5df171ecd7782c61e080611f5f71555ea7423a8db87b3a1e67aa5019d1580088d8565b859e040b6a3206aa91f302b2e41d851098335b4bf949bfd41abd5213e23a3396383b7a6534a25f8d0c408a761f825ed3d5a682b2173cb6d82aff491b18eefd232599d2911eaba537a46cf9527e66e5bb89748705fd030a23d8e99be96b7d41417649b3c44f1a6e95729f9ee9352b8e425fe36db12b8b5692b5742daf018c6948a34818149f9c5440060d62ce221dfa368ff10340090896b38dd0b43db107abe0561c03c78cd50c018ab0e4a0d7c900401767fc8dc6a87a0301e7da3f9aa2c655747ff402b1da9986188511ea89fe95958622c609fa465d6054f821bac2dc99c9983c86569f7e134552da4f4a76e384788b35bf8b7e8bc431b1b1543327657549779888332f6d268ae72471a613b206ba4aae9d16dfb778ea438e1755389689f3a8dccf5992d44fa148f86b6d39466f25e9d1096785e4f7f53dd5050c855234ce0572999c8c1d84cd41f536bbcaefa9fff91700808a791220aa088613a1ce4acb3d4a8a2cd30aef0c1ca5bc65e94ff4c5ae4c09db3bdad9e1e04c97a4c32e5e6aa717c161a3701e9d7579ea0a33ceca9077aea39f57855544b7bb593e3fb487028be5576bec10b774338afb9732d0df6a611ffe14d2a0ea188f70bdc844edbdfcc52bd41a86574b29359ee9a270889379ea0ab7943075ad00a86cfec1ae3715c6c5d99a8039bfc056d003975bcee45d7ff8bb6dd9249b30c45bb08fe77dfeec1a242e5730137e9f1843ea4c5180efe97d4b7e9e1594aa308fc37884d3974c5a9f3f9b75fd14b69c13264b2aeba5ad6ecdaf40e922cee94a17e713d89cb1fc9b5428d5fcbc11475636c1cc2c8b29a3b4bf9427a26226ef29e29002a2e3217f7c18c6c876ce25cc8ac7916c89d75b1c4ffc4d84262d0fe9e8de3dce4e8938176ae20f3f895bca84de7f019a28feb984a2b709da8276f181fba82f751124505d125fa9e116a9342cd7d2917060950a74a160b190a1d93a4b0c0300c5432ecaee1645316def56f4b86882b9f4bf8af8c32ffad761642c1453e05c5140235373c45f8b4792a324d155c15429ddaa31f9155c86f5a910b24c7f4e363eb8738688fb798bf886ffc562888f29c9764e8fae2e216b85ea0496950892ac41703d29f5ff74333dea9416cdd57bdcd28ec173f33d43621e3199cfe82f5260d69342f359d8035065713ddfd533f805b740d82bdd040a31fe8935b71d860284eb18fa382e2fa78785c504afb4ebaa9160e6ba302cdc6337c486276e379e2105967b14c3260100cbd5db6cacaee67545a4d80103b67da2e8cf979eef639ce89433a0450d3d877ac804d801a50f5cc8ffa771bfecefab290965fcd69aeedd898177c97aeeecca8b528a80893c2e57f88b941b53ef7ba2bc12804a88023d4025b6cc59fa4586eabe68f65e864b58c4c9cd6cde6873d6bd530889b498ac94f929ebf17867ae60cd24b1ff7bd722adf91950bc15875422b1c05373bcef76fe40c535d75281deecdbcf709c51cc62ad878fe0c7e83e2ef2b8af56c64db04635f81330897b5608f200c4a490580aa9bcd0a687fde4e693cef9c69c5888594885c50e9b79b22cde0edd112cc32412cc19b96f72c8aea99d99fe9dfd59850a88d6eec6105f8f9c6615318253dd77af76eccb62afe647d91423710b3f1dd750fe14dfe0530232a4cc84fda70ee7e342d236367e06695ec3b5032798e2e5bef4e81b1fe935763a0c5854c5315cae60394ac351698685a48c2226357b39ff00c176b51a6c937fac9181994dad024b2004389f5135fb5727b8d8f8757d862e569e66ac8c98f3a0f0fadfcedf766e411f18602134902168e76056c727efd613d2e30a8537c6d8168af1343a151c193b1f09643396e10e99b8cc74775d3a7839bf5d690928215352f04a7c84522f7b3f40fdec3cb3d79294359edc98e5823c4d59d5ababc4efbbc27d9f196f87655c231a11a91b3179404977398be5357297ce7dedf18e147b148213d650c129b50506a41857ef4c2af33227e30d405c947df9d84b1806307b6a7cb3f32b951deb9a5f9edad687dd4aa883445fee014b2e517847f2d1e4c3908d0ba6571825b0738b0d23b62bf6937b903bbdf0ae9bc3db8ee0827ea62cbfbd60f8931cd64ec98239f22ed01b009dd0d89e8eea1aca4dfa152dbfaf9e9148ecefce204b4bd4e68090a9c4f6fc324fc8125924f299a70eddfac2ca04da82c037a969d465903cfce00b7e06974ebcabe5fa0e04f45eae93af94e7d7e2dc1f438fa3d4a55d3669ca9d420e42b6d9454dcc0b8f47100738037f03f86d823b26addcab3c4ae2462a85ac78f480870f36e38d889c472a2eb3f8abdc654e0ad7cc4fa63cc0c8d89af1540820b94d4438716dd0bde934503dd7bd1050840b5e91d93030511cf705af46f71fe724839adc3e1842c011d62563510f0ec6d0badd2e4d1ebee5f68982807a92ab0db870dfd70c749d900615880b2ae08d3665e2d8df0cd1263e0e3934aa243beb9fc879787e872c76870f653a6f41d6560169b5ed69edbde50739cf9bf0cc585178b249d097f56beb832ef272f3e34775f7ec39a2044e5527a5d66e7e3ecaf1568bb69c3fb030540830aca7d35a5e532e71522dff640b9b62e00ff07adc91549119f94109c11664306e6ec2f3b4f74bb1a3cab42c408cf8cd98b38f2f7bf5f66d8911a5aa941ea9bd796b600434ebc9732fad89c28c1989ed191f38a904f3bb3ae112896546793e4fca3fe710e8be40a1db7bd5322785dc2acdef732b372ca782400670c10ba2bebab6f5ad595f5b5d18ccad71b00d9a1545d5ec82e37aa7e5c491bd5cb4d67504777b2c4a7e82eee2192221eed4c3fa12f4324ebe30bfdfb52efa57d6014d5c0d568204652849625877ea318a1cc53d6020098e8d49a6d009606ba1009b5b666c33de140e9f1b250ff8758a6621b5dbedf94f9a30a8c54d3c999a191443b204b2ecc30955fd114d5c4798f0a8a35e0ae0ccffa1e3bdba6d6f5d75c17d3f122635ebb65d13c24891f53bc8045451d4d0115e67825a32d66f6f309c8a96884185b6263893f2842446eae8a46978dd277ecbbec7a475a81e9bba69f12630169be0ae380b04f9fb40560c24383437911fe0489f3f815f4fcf7e3df676f845f9940bef2f6600188bb7ddec34d372e7745b1cfa6ab85cfd27af830970bea5261074ef31aff9d125d6a88eafe0e18242d257b724ca8ad1573faa954abd55a7f5fd28ad07c53de7ca75ed7d9c46a45ac40818f80ac8e5781cbebe5fa9b83eba4da121ff43dc206e34d62a493231f476b2d43ca0d042880e583c4db68aaaaec73d373c139ecc0741d780baa2e235aef6c31a292724a5f6790fcf1079c15b267c284b1dad6be3ce07f4913a96cf18aa1fe43e3914135e9b0bc22ace58d2144cfdf56734379fb12057d9e46bdf76a9a447c47a6d8ef8038df255f266a3778c7db6f111133ce9b7757302543a4988ab146b887d2c54e5fdac717b2619fe086515adef98737033b3356f671b23f19958af8fc625fd90daedaf2adfdd5df46b6f6906b651329f974de71edcebe6637cf2f35e3101d2dcc3b4f3abc690371d230c7e41df7209f71b96db50dfbdc9c474b28763bade13f286ceaa2026d18468e76c7a20c1152f27a444e798fa01efd80d6c72172e8393e8b7ce617c01ebf5344e1ca4e223b011bd3986c15bdb7cb2106493c56826df4080bb55e8154a388ad14d8bcb8820b1743ed273e260843b11c87ac498b8e3415988776387cfd45d336368f6c1012ee80863a4a692bda945be816ee0251afa99d248824776dbc93d689f500e1c1f919c5b312388ae5542c383a432764ec4ed4a8456e3caf37ab1fb675c421c3af285712ee4710d5f2262d6b38d977c3e12bec02b0527e9d701c5be8ac2a3b9facda2af08ac1909c923d7cadecb994f69634eecbdb60af78936ac4d840abf18c384f2119473a4cf309cf19775c917c8f24652ac90a8f28fdc693b58237a060836e715878fe6cda48e3e3fdee24ffdc51b06113dc574cd9d0de25177b72c8476dc941e2cd13a1db50770fe409657ba9a1b2feae7fb18baa5c15520d28c32fdf9aa59f472b743d393cd5d01d58fe9838b55b12c377ee1aae730bc3c3902de805f78826ef26780fe1a62f4fa8e79aa106ebda5ed1a167446702f1360e31e7524684f019557c9281369cf6b9aabb1f00296a82988d5dccf2e9fee0efabaf701191aacd8eeecab7c07a23638d1fc4344616079add564d27adb66d259fec257f08b6c965a3e2333b9fd09a4613df2e43913963ff2965009dc29864b464b6601105344b135c4e411bff092070109dc17a1bbc597e32c57678a2942d3096a71829344fdeac4edf8ffe48d7024601af1505cf94ff30f169d90cbd06ed0aeeb9d900bbda919261c4c9083018cb37015fab98d78308692818d7bab3ab06e929f0b2b36b62b1408985fa20ae4894b18b977aaee31099f32d84335a80a75a044c37b5005fe41bedecc01216e0d197954c823e9eb0adaaf474278afe97b4ec5cab4ca53ba218d8c65cfb08fcab4a2cc7e6b88dbe534576c8037d79a45a09d0f8a94727ec92fa66083988ed8db6f4d37ae4d3bdad2572736357aeb1f7975e72e51befce311261022cb861491d19860f106c3705be5bf91fa5d683251de239b274bde8590b40b4d78d94cf46176ad0e35a034263cac6221c4b531f3bbbfe2bb1c3e77e2aea73f6aafcb2c0e139bfd0253a17d71d5d1b3bf11dc9411750d7c084b214cacabaf9160c5b0d78ab48d71b854193de1da54c7cf4e17ecc0a663522414de367d1b9d90787f3a2189ee6f82171b00bcef13589a1fa331b12a856bf085a106e22f23bb73c12dcb37a1b262214416b698e15fa35116a59c135bbac96457000324a09d345cc8211c72aa578beb55cc98612a7a7a6c5ffda1f984d61289b218f6e2fcf29643ff3a0bf29c6d521e00f5af97c2f0b6784a332bd1de84cc7db0d0f407b25d4e121d2bfd44dda96d1e857f340449806fad0035587759717b5e49220a15d03c7a3a9aab67e64460e1fc0022c75c1295947323f688ae5cd78638a835fd3ad9b853dd4db3a658a84fded0b96855240277fd83f54598ece96515a4babc5115ff863d1568c0e9a10670eb49d35885618ac7a3c5ba428af5a4b3ef2201f61bded1504dc91ae136b66a243a408c9a2ab77435460aebfaf25734914e3dc7c3dae455190c12a6a9e79b80bb22be6535e11ba188b21b37049bff17ce3c9e546ed9f3e8aa41844926dc10ed7cd60e3b5ffce81972691e6282bc1b07337278342aa5e6124f8201a6f95b37b4a31524ac4f9bfc10d142be2da6b042a178783021401b346e5943149c3a60a2ff706d24b8283f7a722935cccfb14106c3c9b4bfc69f32803a06399aa16030670c4df68f3cc1038c854c8eb44d370cf477213ad2d071b60834e5f534cfdc8f42c3344fe7b31e036cd391836a48198bb61ed523e3b72c1c1447020105b2dcefd72976f5df77fc56abef3fbfb6a8339883e8542bdab2b398d1e6718757c324d174b3b37e43f8ccc966fa5be4854e8ebfc5f0f02930006c0b5bf2cd6447592b32c5b071f32197ece15bd3911287678b92774c319205ade7dc28e274bf098a9f37833b92bccaff375e3112f6fab10aa3a9c75f39c92b86aa9ca8af56b63c83a42deac8de3be12b28de83d24c4acea1e458c362fad4b3f512b0b305dde1c71fc981c526515e12d815f42200855f1f7881f3aec3ddc8b7a35d3a8e6805ee4b37992c04fa29bb41a28a66a53242a6df885cfc6ae12d837e3aa3e8f4b7566c71e1c376a7a7368d545f49ac44ffd7db02ca8331f19f7ea05d0036db0a5c95d3cb1f889118bb515734e557c4733545bf50068dac0890c8dcb67bc961a89fe94b689230e9e5d089be8c01746a180cbcfbcccdc001132137240bf0a1a79b80cc9bcb6f5c779c9c257aff11eda79cb07d1398e4a9c98724eb6c4a9a00eb1977daf627479c39cf29dab4da834329721b52982b776afa9a47996d410ceba43b96ed5918dc8aecb0bd772b5e90e2649271a92dde021aa8d78f0fde782f4204270e0b4013f902eb698e12f320a66ab70c610c8ae9a8653bbce77cd1a0f36c0a124c038512aa652609f4c981c50bdabd0c567a92c96eee5da56849e7e94ed7decd30e4d2491b28dcdcd590102a363cf7e97b7e993508ef6174308d9795038882889c9dc4eabe1d67ffe335ac944fcc286c3c47ff2018a16349c1291a7efef228b062add04c1953872ce9dd62df2ebf4dba65cfee2e8374f9949aed350707c12716aaaa9715d24771f7e92773f79c3ee4a2c42042c0d051c8a63d23c3d53091a18477dbd95cac48f459c6dbffef236e078e2425afd5dbe161fdf9101ffda24d9e53347e74d3bbb394e208c1f62011e4cf51218074d9a64803dcb7eadd6066fae34d2bf3465b24eb678b0563ba399fe8269c5c6ea081f57cb8fb8f1463b91fe0ccb46a7b73f4ec06f0614cd7214ecaf72d16dd3f56312da4b05f5fdb9d2beda1534332938ebdd07b9cb141d3e9e26f7fff296b1949d84f3e4297b2529228d8b98482c399012e388326cc42761310bb7a918bdd5f231e9a82725a1ebc538bdd071fd2315df85d2ef895b5689d5457d207966ffed6f35f6d33a4e4b7b6362d46a4ede686997d5da0793fa56b9ae152db93afaae755bdfabe83410e420131a694483c9db84e1e6745a2d7767eba68b7d61085cbdf0fb482508f3e3717b473e4c86262276f6ab8af07c0cde52025b527d96883c8227e6ef8fb81580c23d28877ff72918151dfa682df1e67097e9451911a3c71a52dad42f68c5f2b351452ae309e193d5ee367a71f389887c34302e5faf8773dd7914e3980071f60ff1efbb0f9610bd05432a69ac13149b15abb4ec5af628e1bacc3bc1bd51b1b51046590c8adb3d931108e372a6c581622f5230d18f2cfa9517c3ad59845fcbf395f20bb4297b00c7dfaa3efc343b0a6a93f7657f57b784fca94a8135813f8a75d24fdad36e2da1716e59fd3dbe8b5ab28c5baf6c9db9a2e20b88b549b3f27f7d3aef1ec54433e854a8a034e5101bbf39f7a5eb38a200d3500593648b4a7f9027796915c2ddb98b81d3fe208aca3790b987fc1068fffdecf62413510601f82dc3569746136e74dfb63ea02c78419a06db5ea59174a752b4276c67f8b89a7cb1a408a9e9629f4469b174153d368e60bcac4e24ce25449f46665ceeb352912deb0bc957d974de73b3c83a6e18aa34bdb2080c6eb73aa0e66cd27ab00490325e3c902e785f3331ce0b15c905ecf0c740dee08f9e0aeba0a7aea0be1baa516de3c5837bcfff7868dccc59f18dd8546c2c826956389007ae60666899b7ba7c1591b568fc58c307199afb2acbc4dc0bdb47f48a03d373c0f04f9695396ce0a83c5039609043a246bd4025c0c78f026fa11155c8c631b46a70f4f66f937fd540585b1d7fd2436b8ad67fe01c59d0fc13dde21c6a2ea056804bfb99a6273ff89ff5ff3bd158b0be362afee154d9b56716e07561bce9fcc1c162c18a92edcf7a49c8a1131e5c1f1812ed44db7a9b799882d8caa9d534c9f69b2349875841b4d77afbaeffdee16620d8aeacd97989615e2d645458743b2164184c3f77cbd9869f43d3e6956f52bf3e094f6fdb13d1c98b0163846cedf8ff196402a63fc9362a884ba7d215c2abe037ca9b64de44e7d9780de3ab9a6a620c065f7fb069245b774881161e0de56e7655b7044884050e7cb5778ab313aba211cb366b865d387cb8c8419c3afa7d6a9aea36effbe15cfaebd93c0499fa4d42e0f342e558a2a13fa25aa1b242a3ec4ea0cd6aa92deea15145c3dd8e4b39277d9f1237a37a0c383dd90805b220088579d921be40db7110e36f8413552c8ba59a5b5d209815a581a23dc95e28576c9da34b27a6f16a4a2eaa3a1b0bb19a9c97f9860f7171ec7cb2dbc7b705be9e3063378bfbdd5841691874d564c7f3babf2e50b9a0af7acc8888c535c08f80f2379cf4f8e5a5e7e6a10530fa769305dfbc0dcee855eb27ffeb9511028d5a9d40067643326f3d90886ea8df1960a5d67a366f11f319570b757b061eaa66b8f59af22540618320580bc4be67c0f008f82a923a971a44f262fd1b029a1b6e0b7ae2ad8c05e730a95310ad0db828bc757ec0cf0718ca9b3dfd25b089d3e607903d2850f4830b6ea16789cd4a8ed36229bddcba12c9d4b51f83808e8c926ec97ec630a0ae399b8d7a8e4fde8aab14fde05654a6fd8ccfc4718faa0138f1ce61385f2daa85f1ca9f8f403937b06fd24f6025a0be8a9a9e4387384ae931dcb2ca0cab697fd712cdca06af994e736ef45bd46a8869ada867f62c36073af6352213074f4098c28613db45a8ab619d56bf9e8877a4c6f76a92e58e9a263c9cee486813b11aebc76fbf9c03ac84268c3a0c77aad5093348147ad2bf4cc390ebb9d4e5ddbc380af802e676ab9b0a887cdf03808b4fe380cec2c94100383958beff8ba374453e5099c4b624d9576cea7ef78934375ac3dd6a884bc4cbb4b8447a99bb2c1c60b7ebd97b9bfe4fca1bebafead3311b34400384aac0a42bc5289a69d901afd214a11c7d9a000278ef292d4d11de0c0e6a8ad74773f0679160bd730c5ba8597d2528989ff6f47249e78915e429d282283a93c389f7bac7eabfc503c8c352b42a0e3022c3af7a5216149671c184ab834c3f35cadef2b92dd99d094f61af687ecfe7d49bb35711a7af0a6adb5f489ffac0a44b6473f9c6c78885b2a7b5dea69639f2363806a88b1d49e051c12d52499bb5ccf6b366e294610688e8eaca1fc1f1f5abb6a8b9466c9f9ca48bcec4a855af69bcc1c8e3046569e8147d56c6908cd870a2ab93be0e244127d29ca49be5b88a7715ea0d6b090e255967e4d626c50eda0a1d643e3ea1b50a8bbf2abf4bacb60ee9b14c053511b3ba7f6f0d771c4edf5ebda7629a6133d289fdc811aae78d81fda3fc571e5acec9047fda9262f5e226c11b2ddb82872ce5df5c332fc02c5a96b8fd75c3aa76d4f3c4593b36e0f1020ef44a5176267c66d93efa64a0b25d24d6d00373bca466c6355757866ecc73aa4e278aab26294a3c40c0264320938c48ce8ab36a2632b3c78232a67183e7a58f916af4752f3ccfcc41e3b6a403461acd882aff6082b9a7bce5c61b125c8f0d75328430728877205a7d780a923e47e90a2a1c20a191fbdea0ba5c60544c21a56b24378bc24f5cb2685c78522cee77bc8a9b335ecc981da4b135e0d86170d2ca4619f6e4ff192bffac1eb50e4dc83c4ee7f0747f37f25a0914d6bb32d0efcaeed78d3809edf2ddc79e28be803953088a66dd858992864041269866c01b817ddb4302be2600e7ff8b2cb96c68aee6b86952a1aaf5fdad87d99a9cb31a57d95c2ab12bfc2f5e9b38000c47a59f97f096d2109417f5d3dcc18934dd11296991ecebe5f0076894efede3038e35e1f76c95ae73c0695c4d5ae634855728c802bcea35a785c854a37871347aaf563f10a0f0750857d2010b2e2a156a31fc2f027251322d27b641ef2c8a38132e5820ed804cb1493666afd571935f99728978b7a73ec6282d86f30e96119a682716ca3861ac1a4c8bf3bc0a8afc22d59b28726ac53457fef4cdc2b5da8221dcf157c3f5f94f85c91d61329553776b19e3b24c02c98a4b361859675206ce217d37da536f993c1d861fe391f696b6c92c21e3ce481418943cb8ebb2b30799009d145cd848468a890284b398f64db5c8d8c463da81f34b5ef7e9a434b4abe89b2b483078f0af5d2af89e4738768143fba52427aa2f732e3f1d3c6729215c5f3a13b5e05bd1bbac50ca3dd3764bd322a7676076f976a94ad051cb30acb3c3805c06718c311a1603dbbc4081620824ba962457b2982917928139eb15818c3676c48c555fe63fda27d46941953c3a2180dc281e0877951b47b27bcbf253aac01723b16a97700b34758543268720d9382698c84356da718cb4b83cef01048caecfe7a4b56ec3ae33ad0b2899e44dcf705c0c769303d2247afd51c5670812ed9d80ca63989ba5252eab6cdd907a9b401f5b1dd0d60b36e8affaacb68fb8d85741a064126790fef4b9dfa13454c1050a17d38c47de1748e232b85e30c06e41bf1443aa4ee1ba152705c60b97ebc555e25a30b434cf6df1ebf0460633358c0aa524c90d3281ca9d4001e478be19cf5582ee21f2d2f44c27d1b612315350bad4297bcb8bd4e472b80ad4242fbd06db87c5ed196402c3b7a46e09a163375c6ec54d35f89a4b501d468784b35de931e83db26adebe43c96f18dbea1ed8e6ccd0f500b197e592b456cc84b09c2275e5ffa61cb5844f688593aa5a0c6144a2569b355d12ec9d8a944242588c1629492acb9bf98ecc56964f368b7506499b175cacef4032d9f467812f10f2b66135da43e65ad0a9abd5ea2dd9c2e6f7f489ca4228fd137e72a36fa05fd44616b78f4b50cf17c90cfae4e7bf17d59b74281f272cb167c46292da8670c8fd7a3aac97790eec30cde4f9f1aee6fba7c03778dcf0ca50363ad2978e9dbc0aec5b957577513bb162943a06340cff42e8e7d8d352c0e749c96908c28973651db8eac9119874a803f65376e1639ba6b115693c7432442e332b238315ba8699bce4b9cd77f7b5656eddfec9d9e3c45c1de3558012ec0d458e06f2dcf9d72ab75397e035b4487489eca1b7845fd221398e679d9a22a7038cfc49a12f2ea79f4a98cb087d3616781d41161c268b1b683663aefc66e0bc981d47f83e79cc22f82d8157f1af15f6aa1473fab5c4666cde8003f6a68206c0b776a2ee366890feed163304898365af5d1d8306cd20bf935bac2a6449220cf939ea7c603c32bcd42980684423244b1c059ee66c12572a2c3a5bfc50aa15078b8da02ab31148d5af1efa732e73db2121848fff1a7439eb42af160218a169160171cb7d4a68bc325a5090df231dae6cf6165f7ffa0772730194929b297147f33c00dd47493165633a0b4709e487a7933d4d954b61dd0d069b65deec452dae73d5aed122875f1db34f062f3809a5dea06dfa7d52c9c8f0712f9f1e33010bda87f9cbbb37e79be2836f6befa0fbe47b7ff85d661c312832c9e23eca1b8b6f112386a86d95c599f2d6b56878a92077df9766cc9aa545f89be3e689cadbc0c4752eb169846c519c58234f1c6fa80dead3a0ef5449ca443c94a947308c64ce404bb4c7aec28633988c626638f34cbda03548a11c7b9421391e13e894a76ab23112ad7e6c81185f2ac54b6484bfd5b769643fe4a66f45f671c317d96c9b1812650c84c27b205b706ce5e58bbd3816a82d1ed00c917bd22c20e6135360dff03bc4022e1a555c9604193b61470142e6dca4314103950d0d245b1714dd9fb0cd2b85ce1b9f5717ea4c50ba6cff8de81aea95cb2785b38a469327500c73291b1e20dafcbf89ae89823b2bb1b08888cd91af4f93b88dc250afb9db49b8ee62e2530a005506d6d82bf55f5867e69d3e79518efc6a387cfe41769e3a54563c8c53bf330110fc80950c6dcf70247b97431f3cf3dc918dd598165302f7194e5fb9d7fdeccb82602cc095a7fd4140c554c0cf7645c6380cab5a8d828a4fc546250acdc7b25bfba93643ca7c1ec8714f351e561ba7733e767c1f8648dbb6814ef82066e013a804024391495a28a380f5ef2c2934ff9835612452cf9f46ae93b17335f2f537e9e8be91a3c8c75569e69f0fee2fc1c062617b5c7b5dcf637dd9c7cf4fca09fb421f2c57dc95f42e317eb434adc93926bebf542e53f219f3dd4b3b78c9957681e69ea5342e93829d999d01c1339dbc61b6b41ce4cc31274846e6f82b61342c715fa7f1d3a79b648f760868d21fa3f0d4d53fdb6668b8d3a9655a2038262a7d7c59c080fcaa223e8c0d089337a71d89bd626ba756effd88d9c35f76ab1632ba5db0903ea287e1269acd6c67b419f10c6b0bbb84ff3eca3ea23e15477ee531da96906e6a0e4e1765dc02cc6a47d5745335124af030ffed0f8a6b7e8df10c160a0581e87294350e53bfbaa4ccb7ddfe5b97c53039769da071aa884e9657582ae232eeb22d425fb338fb3c1b4331f975b13b4d4628affa284ca3fdf76803fc9d1e57d1abdc4b14b70d2cebf0176301e2ea444e6582d6f2e909e61950932db1a12cd5a0df94af76d418ff47369594da42db3ff997120b9470ecc919b166d4c676f460f8d8411c69f5730e42c1b8f8544020c36ace7a1cc71bb837a95c728e0382bb2a25c0f817aebc8fda85b28793eb3aa22bd51a03ad8d376efb5b996c26fa9430ec8f106b1e13c3e544de4c9aed52007b6eb4a5adfa739a13d27e5eb369cfb2b16c1b55e8ded664e8c4acfcce601d2e7c0b24cb94382b6151e5cf70c02c631cc325b3f7c5624f2c6ad878a8e64c486a4fc12240a7b36992500a7a20c4805437bc33d5aa34428fae15ec5f30156cebd462cf4b64aa3512705e131214a59fc9cebd74699f8572800c42946db1a6f7be559858574c1b6d33cd8f8eaf9d8d67f86009c599cccb976662ec2070535836a36480e95c648291e2fea9fe112e9585e0fe0234dff9e70925e456beee2ea810b7e4305ce7094adb0931d11f19ae6b0483ad5fb1c115dfde7d01e2caa51a02ecfd85f6e026febd6c16ebcee54d3866e605fd02df8e694efcd1794a522f2b70864c10bc54db3da31ec7659c77928568f133316a16f9242ab1a8076185f05efc20485f593a708122a4a785c20052d66548b64bd55b899a2b629c8476b96e288f2f4ee00859c6b7e8f7450cd82e290894792d7d64776ab329b9878a45c655fe4e6ff7ce5988c1d5bec1dc414a55305ac4378155657ffba15d07cab61c47fedd1cf2eb406035690619ab2442450ae62f1808b1ffa44b6b0ad2fe31d4df550a6afbb7c01049da3b2dc78a6d49aa8912c69f0e87b570c2528429c7a8f7f66adf0b993912a9b7e4612d3ca01a90a759cb2243e4b30273145e0e3857a59f102164073f994bb0b62f3c26d3ca28632e4250dbbba62eebc3725b146a0637e5f7ed79022e60d7bd9bd4f5b65e41931764896c9991694514d111d25291b166a3f6035381e9e3dd80aebd5f4af4002936709d97100e4694849f6aafeee68467f0bda4eaf196009202330fecc388d629703b551a9ccb16420208d6c9ecd4c21cb611c704963a7e83b0bee1d4474cc5e853b097557042d60d6cd681232938c5bd48ce1ba4580464089aa58954ad2b97c8be0c1defe7ccbc62629b4fb33eda6a34238a14714ebb6d4cd2c57a8c38fdab0c8db584deebcf55a5200dcb2690920b5dda342a2ca6e9dd214d04e842f6f1619b4344779cb34f3937f7991b90b8436ee27ae856328f5e8499430240ae639ea1e8d2811e1eaa10ac521f2b93f867a97f419484da528ff656dac6bcc8d6b97b819825967c1502d97a9b72987c0e1abbed8b1fd6e13758a26016dfb176d6ec3cdfb1f6558a4189882fcd67f03f47298760772bbe1a45eea399978149165639bcdbd72a413b4e27b51fce81a3a980138253eddf5f0a78ef7102e58e3fbb0459ef9b4a74308e56a15ee7409f307b7e7a4d540d847e3f930d2b520b91f78f7a68b96bc8af7fe7361023ef73fc6ae1f198aa65a649f3320980153eb5bfba5a0916632edcfc8fae7e5fb2cb06bdc39708ea15adb8adb104766db86a49cc6f19cdc6d84c05e29456041cdfbf7e614118af24572c51443a8d7fe23d0419d0418ca63d2b29bd549b9aa172d4248ac0304037057d2be4e66bc1bc0cfca3eba454b436e351fd21de119ab29c55bfc7ed6f959139617cc9d44462055a7a755803ae38ec0299ab5c2991122f17f1cc29ff0f256ffffaeaf49fa23d312cb820b048a1a1b97e4b8c2712919f8f0926003630ec34d5d90df3a0650cea002923bf938001eabea736b6f478b147d8c350048002ae8fe09158cd0e8084a33d2c2167867314f22143e8b7c6e984e064de6f927522808511e93c72db1257247e27e3371177338da69fe74f19dbe0915bf1e78284bede6e459ccc1c214dd78e88865f4fd4c54030ad3eb5345bfd75971a92041cd51dd152c7d401141af99f41389080bc8abe0d88bd25a24f80440b7e9dddb0186ce4df580a67d84c241bcef7baae8e5e486f01e58f71098849159b7a63e28d863e6318414fff392c211ab690f0b903e177c306a3cea42a27dda5a98675a1e0f93aac978f2323abd8d1fb64f8a2d8c35a729fab2d6558c8f3feffa1a9a4b8b4eb1a27f19996750a21b9fbfe51fb96bd941148d47ad5f7ed936de13fa3559d1c69ececb64f7a0952b2062c82d6950e0d743649f448271004a94f0a2cb9a1c6eff1abeaded68fded96c060f9f2a72da55a39de85945850a6c437ebb6f9185129a7471fb0e07db61e1e3088a23dfff7cc60956786d29a17e8bd331a5a9eac21dbadbc0babe7c50ddb33c3e6498fa55ae935fc026b4eb73c0e5e7d7cdae183f2030f7a42d1096a67bbceb28196f7052051c20fd8cf497cd34018678c9c22c232de05b271780892c46699d3cc00029bddfa37a48758475168933f3c0efa7ce115cb8a64cbfce9b1903ce01fce9812c418ed8f79d86f1f91bf87affb1db78b6cce7148a125e7e7dac63fc3336f6e1165b5d41cb680a7afd6922751160d25e1da71ed1223c1a470dba9db98f74e30ab1e3eeef0c33852207066ced9179d0354187c05627e0b588238040e0cbe291ea8100839b827a3c83edbb66d4352e38ecffa0c9840ed47db1714352b57dad17db5286da069ea8644db5e13cd65c83c05c13085308eac2326d7f7938a43965dc5a219c11cd0cff478917ab1166bfff74d06b08877172f124221823621608af7f2ac31a44405d82919c093f14af721335a7ebb2a24dce412fbd6423d7015d803a275e74c926ac82e9871dfdb1721f5b7d82975c6965678806d07b73769ee263bccd90b0a2a31943ee2006517cb676c21428c2a9288ac8bca9edad659f120625bbba91710db8f4db9e332836a5dcc57cd319e62bd67dc2e6c8de268ea034121181d546d6e9bc8a22f98946d0fb879e252dfd7b143cca039d533a75fff3fc7f435cdc47290f978b427e7302d0f3295ac264226e80d9e7a416497e4998a2dc0e80efd34ff95b7f27fde0e3ffa16a7373f41877f534b3ef17b3aff7044a5cb19c1d18b929e0fadbd3588eaca710b41859f0d23d2aabca471f96b27c2726b84767f124f371da9c567a0e354fe68896417f11096693a97d296369e1eb4f6582b8eb622b1da66ba71655ab1c6dacebf08b926f41b129b02410bab4a3db138b092c98654a22b667e9b58b2233a3264f8f3ee1afa704e828fb6a711c3318606a3c0bf3945c97edb1c8d97edf039b1405611b9f78e663b88da8160c944b7f1bde11c44167ef457acb9eba4cb90a8d747deec5fe9020375f951672a7f2aa2f789cd69c26adf59f491a01d6531f98726940f289eaa9948b0383a5d0d7080fc44654f41d8e1c7fa53defdf8c873cfb870c6601331f550f64e42da4b3f039829ed8beb9eb4f0706942b7e05c0c3f524a9d1a2ce82c1bf6005f7920a5c7172f32f1527373e7f22373a2b998362544ea6ed28fb347717969fb8fb987177266a6d57a0346d75963d749228e1eb67aabf4c36f5a6b6ecf291cab4b65f6f38ed9121aa75e01ed438a4132ba83be18d77716f2908a00764dddb0fe07abf97d3dc1920a28639a77817cf108e5c6591be5f9947bc97ff4d367a6de36eac9446ae2d98c8eec191d8fbd7df3728946132a62a9366c5d9c61721f81aea01a1edf5c25970e4195eae9d8603dfc52798278b34994a3ef5bcc3d7ee92a5fa0b7762e7fce9cc266f0e70e32c6521ee5cb22281a89bedadb4b5467a8143aa516c54290aeaf27e121a1890372efb3a8e8d25870cfcd02a41adedd1657e83d304ca9d0cc607dd5081b6ea71804ef7a5e4c5cdca938e367466a370283e57474c53048bc8e97f9981ede51bb2731a0f6b54d4661b335d6971fc8a52db3a517a412a0895e4297104ba94b84205f7752da537c3f6d621d5045ced4c023a355ec763c7b6df5e79b781363413054fc5344fbdb9beaab3eaa3c4b6863361dfa8cc98deaa23cb315cb27fdde6a47b7b137b7dca68d5619d106981510c0e2c2ab58af59c93a01442e1d1f62cb019b06fb51cc451f230ba7a4cedc06150b6c32dc855fa00e20e3dcceb95e215c4d20bbc1c72420fe199dd7977dce61a95a09378b8288002f2f9949bac5206bc12a5500322fcf9f0be1254bb7b7597d46b80cc4c40672854a8ab62b566471505d918362c492837bd88814cf9f8b5dd07642d5d96bf62927789c323e2fe46c711fe29971aead01487a970931afe78770f72a3a0c452101f0b9f51a08f0826c17928841cf59368219c8adbd0b2bdeb54f90988cfbde78e2ce4bc21e5d596ff7e38d5ab40b0f635fff730be60bd7995b446a75fb3f2d929d50fdc6142169fa5ea51550d2760cbbeb9a5fabd0b1b0b9a9f6fc8b2c53ab7116f7e6a5cd454be21c549a3cdfa8078c4c7de501cdf3f6d09dadf61dd98bf7ef4d746a487c2704bd7c5a2623250c20f3b74d93cbff7f3f53f835bcb4694fdb6086a7bab66cf1b044733d40a7519853443a84e8f75c0e69b2433dd93c20365e45c75285ab56ca166c93dd56686cd48408c8836d7f7757df1d618d5aacf23286e8ee479f83d2f5ac4b1472d66aeca48e38a0df6f7cae3109f0aec80dfff144c488063823c2675e134ef49ef0bd1d45114fa899336e926cb56d5f7d133cabc27098cb670e929e00451e0cb680cae2968b31cbf6b0eb4c91e0c065bbb1e7c40509d89b0fddf37baa954660cae950fa8dbad742c159a3e921e1c4fb96a56658b48a45cde3cb0ad1f881af827683abb272455fe17de0bb63e04c6addc8a452ae5fd2f6de7f7f6ac86360094eb9e41299d7865e868d35fbc95d7c4dafee262931dfde955a8b8563b373f792992dc99d8253695f1732e1eebfab2a9faa46a7e1231947c4d883bd02fbe3247c242013c992546165396cd25ad64177095b96b7a962b8bac46348ca3666a4488955ede05aff913878a5d32cb71a063584a00b5230724cffca66304aeb16fa289c93fec0d573bc6a3e8152a83b5b2f54e3c70ec2287b15f8683f2d8ca2025da026a290c6028e4a7718c5801ec6185d9dade9ae84bc18cf5688b17b011a7c7b895d4dcfaf20f78d15515cacd8effbacd2c924957c26bba677889d9a4e6bc9a26b4a5c82010b3ef09060d78dfd11ca9024a83965395c194a430fb577a0ab226a70ee527f917abd566bda2a5d8c81f013511a9faeb6d066d44d14623e9352fe11f342236e96dac06b95a1139176984d18138db7db2ef414f56d03cec50a8bd31be5eef1fc000a4632c23a11951ecdf706a681e4b16414e04eadc862114b1b860bc4f5a99e3e8ba0f14009f282d6cc3e3a7e0bb062bfe1e945297e167b55509b0e6e638ef8813120dc60a410a2914c08114af5a69714c5c2c91411df412c1345c3da306d67b1a537a48d9c5a67fb577d4000981bade903869c71e3edba99eb06d59ed5375875481316fc0cea1d80515f338faf228b1938ba22528c270d854eff28348d9656e3d657d0cbf6c1f11c4bb4db32befc3ea603d8cc2b9b2eae2caccfec34d22a4c610c1d6064df56455bf63abb8b23afcd24fdd48a91a42e96a871d16ab03dc81aa86589103ca2fb887c8baa7cb8da67102aeb3f8858b955a852e88399f24d741545694bb80e58afc2ba4c8620707db54e1b9cf20aaa0c6032789af8ab9c3c19d2156921b218b9e60b403bc39e78e8f316be3f61bb22534da336e700d7c43e34625b5c8de76911ceb26731d5d95329bad45f77ab9906e4a3b879761421f2f6aa3c9be5044381a858ba79513beeade2ece77089adfec6ebf19fdda8c1421a0d5896539e19c22d80ae221e37efe56c0759cc7154c122ff17e11b4bd69d034cb04320381076af3be02648e3e8f62ed691c5595ce2ebd1a31a5561771ce998df227795a26191b93306ea21cacf436d76101ba3ba809956760a47a55943699706870e55c6b3681838e41e268c7325aa0c34a4596ce0bd6598ffb018d092ad62a2489e57d430cb4ffe8e9af0b9c3b541a4757a27b9f001f4433b2290f30e2cf9864e6a0ad5b6cb289ad905669943ed1095c61fdfaab15c49b012d18412cc5c7092c7aead9cc5089817ed248a7693178b1cf7d58323aab032e45b252f92f48c1446b163bdbd887c22361933d9fb682831abf10496ee5e54ef2ca7372bd2acf2dc6147347ae81f6898ff03b2c4534db3905da279cff6daad2fc5d80f37e810a3adf486bebca119726aaa833a608bc33feac62abee1d7a9fcab21d465d86ee24212b509488bc277f9b377806ab91a9855b50484c0f9950fafc33092000f793cac585fa20b8bf969c8aeae87cee9a9d8cd1646b44632926e166d87269704426ab9c019606800d044d91820d7dda82558b409780f7dec9fe6c2a54524e2a8023072f109b4a97b87a140c29e060aa90ddefb4be33d4fc66b1f05a3f1fad06063c68e969d42692666c672653326bd13d4be602c02e17c85fdab96e71ab34f9dffd7554656d6b794936027b1e108ccec3ce9ecab842c40eef989a7d0506f135bb25eef692482e69c196a6fac487c9e0458eed9ecd5ba701a7ba70a8d6a2d915064f2d2851f9655c2c16d086d9b6e54383621ed657c668f762281a670b9245ddf48480cce13240e9326fcd509a990b1ae17eeeab3c59ac29bd35d4ba99e9dd74c95dd5059ae205d6b7ef276436a395a5af10c4813cd435112a77f7c308bcc8e4743e813057b6290efb775bfd86f8ceadd1f25db8b40fb2e71a0c8d9a9676a464862e3338f21e0e8ad86ed6fe521e4085e5385ce129fc6b5f647fa793bb37703baee489da70a4ad824d39f0136dfbe8f009aad7d8b1048c6dd465cf85bab9f91bf19e50193062dbd62fd790b401da7ff6cfa2018c1f02d4dc51ec791cd42fd0696097973242d0d7d3363caaa39cd10281b2baaa518f897f10dff37ee0c17fa09bd1cee97c2f1d5d1c3e76c9b307f6d215c436932b17b295d0cf45c4f88bc30e08c5f86b6b7a5eba52f175e8f1a6000b6feff737e6322c382223b2d1120ce7e5a93063608a4277f0087fa9569a058ae22cdb5f059cb1e9fe6c1062ccafabcbdea14d0e73034d324c86e6248d85b686541ce25bbfa5019904f857cbf253babaa713f2461f6c85a170188fa3eead2cfa4cb9f2b8670ff44dffdf4c52125297bae656702c9c0a4f7f59a9172359237d24f7ee19a92d2857a2598110b319c030e4352fbf701b3d88e8a6a916410cbf608b910c9b3590260457c999a0b34ae6807dd7b516d5756980c2e2b6d2ad504a1d29e5381223d91d9001d0bf749a81479553c7dffd89e9a686ca5eb43ac17b68d4910134e93f9343b54bbda32298b9468b0f2d3df8d1d7ae0362bff8d391ca98ff6003308ea5d57efea51ba11084ff3480791684fb94a644131442733b327bf183fcb2d7538b0bfdaa3b7dce5b9c387cc47b05f5f9d005e0df58a3d68de9b7653ef09c2a3b07e5b9a8b23ec5c80101418ceb6f352e6d5f4e3f026a694de5fc33e0358ec54cb573812a95d4ab58d8fb4f65c33e376f9de46af2fc706db5ef89fb71e54d2924e888d5c8cb959e96be17bc750177778fc7b53f4ac68a548b935ffbf758ffc08ac2016559e7441fc84adc9efdd678bd5e79a081cfeafefc297258d0e89495cd516f78298959d91c71bb1acc69321b5eede4021afa4808a30b6e5d2aca3b2c6cd18e89933c591fec65821a9735ffad61caef72c3daf0b593a6f9b61def221613a0c60ab0a986deb351b286337fadc070eddc8f8a13d538bed868125dda557002f512c35e66aecab04f43118cd1dc67b1e492668987b9c11d87e0fbfd69cbc4a927974f6224731b4b3baaa922069830b6cbceeab32fad0441a6108852d9878c67e3d025d30442d70482643c20636cae7d635fb8a481b0ac57e105a27014b89bb2ff32baa0a7abe5f5fc104a3e0c332b478eaf729c9761e09e25b4c7ea4c2e2599bebf742ce0a7b195e7577ba699572bc2ccdfeda5b3e6e86fba3dea73040a360fb369170dce53a0dbe7bbf2bbcfe617bedaf86d8219aa5e957f08b47c86592d049ab84d54556cf7cedba5ca3b9d7114a00fad105df5509696fbabe60179fb9cfb64eb97fe9a22a40968ad6b21cee98687909ab33e89b7f88ddb39d44c3c23827b214e7ca0a4eec9e9a6705ecd63be6e2b7971ae121aa12e65789c5c2517094ab6dd4e714eb26bf4924698fc4b23b2be0964669ae839379ada572792ac4444d97778076ef991c78bc824cd773c4f846426bbba9544096cc9a22b8dadd5b775d900cb868ad324e81df3726dcaae01296729557115758e3a6d95bdd6cd8559cae419004b02af5c0db9b6dff248d5cae0548e4eb2b3396f0570470a894b02dd35cdd4204df1343d524893bb9d5fd7614b412e6b31679ceec48d7e325de1e26937ed7a268238a31c5e7a24793e8611e33ddbd2aefe5fcd39643afc9c50da20e927e60408fbfdefc650e10a1eb2cb0138f237ccc23ca326b39385c9ac57a432d65c02490d23b7c511582a8194de703c16a7aa2e425f24c0c0fc878d7270aa830bc6ea9bef9267df0100ddc50809a5b7c93161cc34fa3669fbae02da71389edfeaaa7adc45578ead5c29db382b7dd0364af8485d351105c8b99110ad752cf489932770b89dacae32490256ffccb418a7a7a6e0e0d9fbecbc43788852c131add019547a00330c99a06e661074f5e342f82ea8954b6326114935d25c5ea9d2f2c8637c890268ceabd32b8478c930c00a24daf4f0e91f7f3a8902ceb2cc4cf57d3aaca4121cf512adfef4b12c7c7d7e9805ccbea8c48740345eaa0ce1859ddc6811e4ad06c14f2e2c5e292144262b3710465ccd7bc93e1df5da432afe93731dd0d79419fdc7ed497b5bcd40b0115a6748ebb37f27abd0ccb89d23d73c82390fb795d1a5be1c47bfc55344d2ae19a993994a6070d3f2f9f1b8e12da4a6305fa5760ee033017df16b2fb2d226428f07bce9c00e2c26cdea72899a416d550bbf36b61d8fae53934d2be7b097bf19d08f89fde20b689e67bea5769056b5baae92ec963176751d7350bf0d4140593edfd0cfbf0fb4080c1949219f35c86e6ba743e7a3aa2327f5f0d43ec003e87c09eef6e0fd3c1ec12261a7219a1211b4d8e129b738fa307b4cfb1beedfb0c9fed506b39ef3262ad85accff09e86d6cf76570b8759c1b8adf09a4015d132a062676dc11e1b47a08a4e5d2629dd66d1f29d74a5442e558340652f08b733af5aed68b4c13c840cbcb0e551eff58e53e1af13dbfdd37a6e0d9e24c66f784d8f41bf782f46a5178bedcb277be766b65c2fc8240460c36c9823b046c1a84baddee47ea932b708c526e0d2cc027add1977781c910d0c56963a4cfb4866db1445728cc620b84def08f754a1ace263678c0c8e8e7e7b208ddf28a1cbc90ab74e048b71ca676b51a0c8cc9e6eda5dcb90b9c53d8f03d391fcf8952aa3b3e1fb6b4b3b8f927932a704ca90372022149fd3e6ddfe7c28e48427c801ce22d10038180cfe8ddaf13a9d290000d33d3f00a661f3fe82c1f213a1274c97d35ee26efe0b65d74d8c3a0625653835e9ab60d7addb611338080bd3cac2bfc40aebc7e106bc89510775ac5ed17ac84de15019ffb6eb4e97e856316630a1f8723613bb86c8ea340c4565103f47dfdfc66208c7b76db84fbff7e7716c7aefab7caf0b4032f55a9ae75446d28aedf10da3b90e3106b2d9b28422a2f993716363bfae973ba3103d99009f2c3dc1c2ecdeb66365fc504bdc5a595314fcaa48c3824df59277b8e57b7879fabbe1b128c84e217defdb24599defc21fdff1fffa43094b26b52ee58a21269ab2ff6216a275ac66b83e29a8e1a6e75e86caced28986b45516c37e81e0995b239f842f6853dc4359d709c5fe288fe8b6da878e4614173e4611bf3609686d2ae23eef3df81ecf8f1abb401d5fa62a1cba9e8f78e44f0596e336345283e9e79ff0c7f512f493d32a578886a40f6d52909817f188e7db213ce0812e2c6686fddad3075f5ff9d17f311c2d8d5b635389ccd587306db1dfbfbb7d02b6817a6d1a1da90c0db0d55f31d1cbecef5ab8d665ae26ae26957ae52101a21aeb47af7b4769852377a4a83cc1db04a40b6f166ff5e1c8d0ea7a32c4cf453fc491c9eceabccd3c6390c46790cd2738007fcb81d3ea3ac5bd34e47f2582984059670b43819097622942dee2c25185e7b50837cbd590a6e12c51a51753163cf8c8415ebd391331e347f60312bb42c87b735fcb30f1f4e93eb82a169d1cc55bcdfeb219fd944bce343e942369e1af26bcdfc49cb5b7689d48660d45399e256918b84548709a5e01dd1ee9b56f870095772d105fb6802d2521590b7c2b86e30caff5de0d1751e501f10cf311359f0c0847451bb883850c77491e7e530b21cb550198f2b868ec61675b60cf008d7bbedbc1588507d7a7d68b3eb7480bc508f385bbeff7d9a684fe0f73e91e44c72a032dd62110748b0c72d912b736840a32305dc26014162ef75233f8ccf1468408aa3591f859b4250817fbc11d8fd2ac54828c583de40f9f77657a966c2f1e0542ba6442b3e8576481c29a4598260a94ac1afa0b6579843450565177112ca28872ee0924347e36bc40ee5a773cb86784b2c6e548c8ed25baa88ec553b07c32a6c11d345827e7af7f18eda3be3138059df1325af60e4bd2e04f8197e6a8303de58191a71e22457e82e74359ac0e756f2027a214acdc146e10b862a83ed376f97c9b7beee62016dd6024653902a95093d5c9df49a09e9b9fab953cf699828413d95a75abc67370ee58591b6ca46f3a120eea6815012d58fe04a76ff0f4f348783082dabfbba970a798e9e66674b286435c18c0101c4044008877fb4eec70aa72ddfd15aed22ab46f3e4080765a6e844210d4cf7db05ff0ff15d1115f3c01b110a283c4fc975028690e066b38e67e107d93f1d1d8366c8370c5fbbc49683639e962fe2862f9c8ec0ffc105114425b0f8bf4894df8e0d1772844fff0c027be9a84fe0b09d98a0c4f689203ff5b8611a25df2fd9ab4f1b7608a8fdf6ee6f3b31e66ccdd35ffe4140b47a1042340c0b3df20d7b8ee65f9c53f96eb41a6e1d1209827ceff276fec8eb008a8db318fc9debc6de890d9d79f7e3f161d913e2aef96b8ac8e72854301e1a16015ed7d96beb8bc5926b805a5b6a8a9d5c87cc4c8cd5b3422456bbaec3afe85cdc17031cc6816e07ef9c60a27952aafade8543942611c2f45d8e995f4b2d693b846be455c771c04451e426f0dc1c7d84c5be94d52b92e60977cc69b846c89b910c6a918a93f2b60fdbd44ea8a649fed34afedea73982af9ee892c2b1414b1632e120d09c1497124c1bb9f756ab66752fa959e3c0a496d8eaa1c397db5390143089677ff795b291d24ddb48fcde3bc8edaa98ff54c1510fbb6bf39c373f6b3884ac60acdf5ab16fad81fafa48536216de01b4c16f67a284bad48440ec28ec33abbcaa6baade5019907aa9b81252b8ba8f2dfa7edca0e6eab4dacdd26596d56ad5e0f8a7b91d9cc5afff2a484bc4954bc4feac1fa09b9814d59bd4d396e62b2559ecfadc59991e70af8dec336257bd15cb9c8579928efc377fdbb239e7280b8e6747dd20395008a5d6706d9161954ce718103eebd336be5493078e50954e3dceb493eae36f052dd4db9a539b8ea3bdc6c213f8063028bc68d45c71ddc35e392bd9e103a18db03c46e7733d67ca76c147a8a93b73e76ac2ff0ad4b27ab42c2baf32423682a2584a787de4faec2fd7e70a5ab006c59b3d277d14feb825dec46df3162fbbdb4b21b123bda7ce50f91daab215d9b7e0fdcc2b5652ad2c3ad19dbb6cee8b06dcd53d97996d3e690fe1205ed952066465bd42924d94849ac62cca18657b4a36a7f32af8337d13e918f523f3d74b1834b2cf21bff2587f31c7275adbe81ce5ced30b20d1a16124c8a14d79c6fa8f64ec1b4e1b0e644df9dfa6cc9b889ff767bf6177f63207932e5c7323493695ea9799c7a29b0f0de22fa0f1a416a75dc8c28dbf9255306f1838d6f81407d1cd808f64c4c9721f7040edd4a0ba9228552e4c69d1371c95a5e2022f47c2d136b9cadb43ccf474f31b3fc7c2a4e3c5ab9382a254ba8d0a69837cad5c490f04b08beb99b5d1aa19786da227e4049af2bf3fdbfa2b41ce30614951b1127046e4019b855509c0917c9dd6e841aca61b97f70b7a9dfd6aeb9a3f8619b0c3b9f4ba9390abaea6d4a84ab814fa076faf7e12b4fc3f588ed8807ce472379275f5e9e15bb98fc304972fa073097c6e1e3446311fc46552fe7959c76058e6f498371f1d4fef337eb341139f36247432f050f8999856a7cc087a8d52e94bf9bb2dc28a4b046735c8efb04143e86d659c642d59fd7767b448c4190aca0cfad7c20473e7fafb350c58095eba92f7c668c516820923c01e34287fc07e826875932b79dca9f4d92d3013d9cb4eebf782beef763beb423ad9b721208a9fec94dc40e7a463807b8767392e70122c56595835b59250b341c1e4c5a270941e4894a02b0a056ce8b43a1d66041b902ce41761c92593e05726bdfe2e9c1e3fd7b4da301cfdf1980799943931cb5ce04aaa02e871140e6e7ea0c63a36cd1516e0de58659422b773277c6024692d1bbc66fe03a62d51cbe21a39d023461e3950845743b898478a3b348bda022e780ad04007027c970d4e06ddd41e6bdcc99b0d597268a38f5646699cd404550e3cb7811c7d80e6b37dfa6ed5fdd5df0bc5fbb13b131b07b1fba97d57e26f1f534d3b3ca206089fcfcacef2199958f44dc0ab5193d3a1bb8a632f687bdd25d60da475b66026e0ef9653f1ebf29e8d54231d9e1fda3482cb9369abf16d58bd6a2c2c35e084c1f9a825cac0c9c84f1e2ffb5455065d219a63693ee4e389fc0adfbc35d29a0e0017b9327130f27532a5179d2527436ee836856107ec45dff04ebfd49fb9a9d12c30fa5ac7cbde55f67848cfb321d57eb89ea3a4e6c68fd2423e1eeda323db38794069371a4b162ab0e233d1b4aa2558191298e5b1bddabcb0a8a45da6db0e5b5e38bfd0ed360518b13d7097c9e336fc9e39b9af710a2ab6c20820dee2521268d7c867b730194cef0900219a6d9865db782ae5e676838c19732c7e3ac62d9e10218a2f20a5c5c7f98cd2e430592f0c0491cc1631242109e890c5cc4576f19c5de061f01413567e584c299b4f2af7618756911c2747c5e0a173bb29c5d6ae28dac5e0b8d1a3c5f95ce2f8a72492682f5738d92e106dc2f68ab7d1d6c5384a4fdc7dfb9b905fc198f843d2494d00233f29959e1708f66822689a64d7b9608ccdbc5a88ecdeeac2151007960abd2158d59c82e3d8567c40f45bcbcea6e5ca6aadcdb5d7d901e7ee04a79630f9902a91b290816cef6934600526caf77ac8c401fbb7a094c2dffe05437f14db9d52619d4c53fde659ee0ec7db1e63db6b37070f138fcf59fe7a15c998164699db1c65eb2fa6928d47eedf7e65ff01704795bea5e36520db8231409e17b6a4840b62675794a60f88058c34e76a44dc039370f4620922ef54576941e1ea97e751841e0e0615ac18eaa9d0519f6fabcc181102e3d2541b20476087ef96ad34b73c080265918f22b2a2f886f9dc0460a07b90a3a3022bee9be5921f31375f1c502dc11ae822f887bf57dc0cd9e9ff0d5e80a9782cf47ea520ba189d5214af93652cca86e5482eecc709b4fe24df57b4592a8bb1c829af5fa5c5b1e7747940f6602474f1b96e7d552142b7615249b3b20a54cf7e847de56407708951822b28125afbaa85d6593ae2d49772bb6e4f0d25dd2073d75be8aaa462a02ae34c0d3a986c30c97de8123dd989aa0e61ac7851b8822e0e12cf8fbba2f2c1ef129cd8f373e948ddb260096305f22ae8e5e1094b50b71a5752ab87a2d65c5f335b35a0b98b47a2057cd3301959e542dd43374ce5aec18f0ebb6094e66176804be6f35f8b9440eb7a8673f523b13b8c3e164b22065ab0e4854f6e09035bf484ece938f37ada78d6f7ec8fee7a48ccaf0b14a1858ec6aa92a8e1f307503e7ef3a0ab564533ff3f545137c943642ed911fd392a75f96e36bc11d6a3d76c343eae8d0ede026e098e3d8e31f00c2dd6f56bff4284e49d56301b700ecf1a98df2c84b254726e5cf76552378a2bc7c9c873eac25c328b5bed158f8cd7f7cb73e809c4076f9b42ac7ec7de1c54da32988fb5eb872fb39b803bbd88d2fca3ce0ebad50e4b9caff768922530cd1ed38abaa4b426a28701b18029a1baa1b4ee620315174bdf7b2eeebea60668e86a7f771e6950efe17e4a80b03f083f5d422fb788da0d4f264cd54c3e6a8db22fd052451b3bbad6b2e87758eef91f3c58bfa2a6e7f2645ec8edbc01303d2a811038f6c543942bf849d5bf8ac42e7f7f890ae2ad4b9966f44c45152e42d52cd76ab7f157320a76b5940597a210f5a2daa8e56a4608f2aff7d57359b50adb53899de9b23d6a59a7b10b2e87f8caec32e3c0a3feb6e4ac0ee6161779733e19062e9bbc56c5bc1fa65e3b60231441b38b564e8c4fc1e4f3b54fb1647bd0519b960bfc4b33602e53f4d67aa77201ac28ac459213a47fc79462d57579819485251fe456f6b416f696e61ab2e5ccea6b7ebbf29d635730606725739eeab27884f981207b82ad2a4d95cfb8753d10b694833be96301b145d05594301b78c4a25cae15a25af434d6e28f2266e34c5e31e5506b075bf0f5c3e93a0b0348215234bef607856536a0d83d30fb1cda7a0a7f6603c0d40a8cfd4bcd87a72b8262207b6431d468af10754f4016ae4d8a232f70cd9beaf6d00134a9d6f820c3fbd345f9c0ee270fcf2803946979fd95fa4748f36f99b55e4bb55b62abc8aad111f55981c972d15faa51efc067cd0305a541ed53bda1082298106ccbca5428c58be6277fca29fa08c044f3b96e605f27c5a34ed836639618355835a5bdc8a5cd19af625aefe0d57e3d41aa6cda020b0e6c1f660c283890b0e745503967621dfac1fb074296729abc28b5de3f0a79677b1c9b7e2ec5ed45998253398e4b5237b4eb6b87e6173d183241e433348dadc009bbd2770eb5b59ea54bdee32287546e641227a49dfa164618a37f8008a0adc2f350763ed86392b66e961203dc87868c9acc235a9537fbc3d5f8b7b388e4d4a1bf19c011209479ce8f6e918e545cea0f8cd3aa8e25c7e1759138e4cc9b64bad253788b01a309c944bef316d26c33e0a98023d0c19b790840ee84cc7626acdd5f11636e15a8cf78c8e49a29fa5150e7ed045331a94d5723eba17d7d4702bdf14c3887660c1b5c447dd36debc158ecbb1b44ef08c781a65bc0f8d2997d96f1f358e9fd746624de77fea1891de06007ec9ae644600cbc19cf432ca429dceea963325d383d366c3ef944efd708d12a337812726c3c367069888db7dc077bbab80aec4a2c4ea34570f363bfecae8324388c45913d974113d5b894b56dfb04b67a86d631e3fb7531a6b4d5456cc6c6a8f9f503828ebae5d9c597e2d3ed53019c81ed658ca1a8677031c78cb07a5c0196d67f3ad416ae9fb96f86494b882174eef0f1ae414f819bff9d14e1bfe852d5ec9599bf7e64ad20a5e313b4c80585b33c5f98dbb93b756bc97e970fd24994ce201f02834754951dee9f9ce20a93b6027023767b1dcec380afe8d6d3e585f341ff8dccf4fe5eddf2e21be9a9ed5b994a9621b4a3c1677a041eb4c7b70c8e6d1eafda9312292dbfa913358ebbe7499c3f0737cc2447633d7ba7f3d5364e72cc02c59dbf31943e85ba9a1ca3c858ec8debfa3bffd3f86859ccf66c8cf395cea25032f4d03248fb21bd76c742c629af6b8c0d64459bf99bf3421a25d41cc13ffcd8afc78c2e4534d5aaee9c59be18a3d6d54d17313bd6e55ae8d97ceac6084bc653f2339bb0161b05f90084bfa1224eccf5be89a2c0532893d8d49fc4aee1afce3b22f84c8ea5221051cf75eca1b0eca1b9796d5de06a336b9ef04600625dd08272c8fead18bd45fd1a52f9e91bc508502d98e361c2c25045f27c852570cdb44ca4715e359f1916ba060a7ce295a121709b93b6d9eec8bba5a6b9accad8b045e0083e7a70faf167a3e1a651b9d2333056cdab5d1719f9ad6fb86e002156891fab629fcc1b921e507c4c71e237bb83ce117b48259372165428c231c1c8339a882da56d7a8ba084a0802139eb18d7949d6e59f3c9a14b101513472932c494fa6ec378d6e65a251e8cde038f9500974252896dc8329b2fd603ba1e534283ea64498b9f80b89573e1b14d6fcec24e9dcde2df095b413588d41f1a84bae88d7cac15845cb9a8d5edbeab1a2582c590ccd3a4a77adca4e119f3d174ed965516916051d9bd277f8de3538dfb322da88674a4c2399a7ee9a23fd79a9b488e5e8f9a586e76df168323e4eb801128a52ea8b2eca390f46c0a38793e2ab3ec3049e8a924a4c1e4872b824b6a5827483a91fcb05a3f78e70fbc7daec94e99975e48035896b9f09f6a8131660f1f38042b446ac13ebc0e718e152b3050572c63a71b9cadac27c190cc4da324982cb5a3470309b0a194727759f7ca416fa756d387cba2e140318e07232fdd33320c2845b10071afc98da9541f58104b49aa0b5f04e9a01bedc450c2cd0d425e8fd3efd908ff1c62f5cc5af906a2b476079a7e53ca700dde422a6fcef8d7aaefb36de9f632c601ce2fceb6a552c63e5a9657bd98167f693c39f7017a1f5215b77fd6771772dd05b841592bf39c79e5abaf43564e23afe59f5ab9b9d18a9f80b6e4f3bf345198f720bbaedea4125593dee33be2dd7aa74a94b7ca4d1aa8608eb00ecac571383a21c498c5e81498f056354adf68326f6b38e18a1da30ef06ae579d94caf889c1b90722da442a85a9e201b432b64fc376155fc55f708e1395ffa3c40e1d49f585aaf2f9ebf865d2563f1c0e46a18427f354d8ad1ff6ef8de770596295b1cb544ddb582eab74f31d6edf383df601ea1275802dd8faf5354ac7a62964f83c1f1ef1ccd92e9c4013b099c01282071cdfceb12500b5937fb01cd0bde006447e2650375297a91bfb3db44990062c77ebe42a1896ea45ec714e121482fecfcf32e1e472c313ae812cef08a07b7a473349668db9178292873aae518c82858648b4a8a4bbe44d843feffccf741561534505bf02ef2f030c151f2db4461b5d835fa58117e59fe9fd7b0bb3a832e92fdc90fe199569466d5e9fcae9d926df76bc91afbfecc46683986fa53fb9282c12b51a11eb0aa684c35c12e6a60f0b2f8bf66e2927e9e1a925dbde3752face453eb8b9a6c291d9221a035980b1526b8a37ac5a2f73724a7b285fa6239b1488817a20a147cfdd4431d98988dcff1b634401eff10860777d73fd07fbadb162737cacb0cc32a32e5b84e124c3823a27dbd33565cbeaa7127626518df60b9aa0853eeb2b1ee4140433202bff64faa6cc2610ed3b6a071036c2d3a79c0e313fd614032f4cdd23c2c907d016db31114afd4b24646c697c13c2c3de09f7184b7ff9e0ae42c0f170d3b27d2eb0cdb50ff92e41402bd5dc73e94101159fc0cd361da9c8b719a7d8f047c518b17718712fec4d69a88e1e759ed2e7e1b5b7b03028ba0c4ff8c3fc0ecd24b1d39fb299fb0d433a04d5ca80fc790043b981f6374cf3ea215e96082079d9a0ccfcef169967c40ef15ab060c2e6d50b96681828ebf23dc72072823579dff94ba26385716af200af837e72bdb153de7fb8f48b7dc5ab0e296e431e752dfa721e7090d5042d9feed87eea3c1aa9c4afd6280ca481f63d672073f65049ffe691bce0d1840a0322887cd0356995e22359da8e249c6d1220f8ed04d94a710c85fbf11b1d31688837ae12eddfc3c27dafbf09e3a9cc0e8b60ee13570501799c0cc9091e5fdfd238c363e95c5f127b048dec3e5454cbe076fbfc0bc7f7612d272bb92ca20fd6d3bfdfc224d2d47bd1fcec837cd85429fc6ca7a8f8d0e5238eb561c9f029b0b62e6cf9fc5c85e4e0a5515a55d0db12c6599ce17fdc16745ffbc775bed087e138c82abf6c68d22497bbd56e926e47dccc2f8a0cba0ca71940170032ca5f8de7b0324e1745024490ce4609082e05339e75caccf39bec46f39b10296a076076b90760ee0671523a76b714f73fc4e04236c2f95cb9f71e4e6ac587d7281fa26eee209deda126656a3117985b74aef7362fec9c83986f042e5954b84a4b3bf0e4310ec9fed7c927b48ceceb4862e7f4db784ab43367aca42befcf0bac651c722ce2dbfe6a1f3e582616b735a45dbcab0e4edebcfdb879eb6b82e3868a61073aa0e79bd65bb095360c3e16601688e55654eea22282f9d37471dc486b478b4680ebbf0649e41aefe0b0d1c3f50e034dfab242dc79eb314224ea5e8f5e24f975e9d14bdbc7145b143a39f7092f110c23b33f57bb950fbd7f1a2c70cbc9fb86689e776a6909633ece88c4395e0bc102b21ac04c3e9b4daf8d88aa906c6ceaccefa7ecaddde48849f3a5ddf55366e0245e8bb319c2719559ee70b3054b1b1b8d0b2dd9231c22577035fb01db48a82e3211344f87da7c5d77dd8fe7a033afc695c3d90a8818c20847e65dd9d9ca52544828f37d3c1b00fcee43bdc5da2c2c1e207608e710227ca064e99d66ec6a2b65a28a5cf38baf033f9bcee6efc982aceb0c2d0ce8378dadac986c0b386120b5064449d9e577a131ae6a922b89d87d54fabe8d16c7a74d702d0f6625446b9485aaf965717b710857406254375c84efc8796bcc843bdbb18fbe4bca50bd1972ef8fc625362c293d86833905f781eb408faf1153f9bbc7339ccb6dc23657def325ddca19719db199a4be01a16bfc5a78b1843ab1be522cb4a11617df669af4862b601649a0d48d0455543abf86181c281cdcb91331e259c2edae61c1c287c60867f3ca89dd9a601abbe177fc29f95fa54838812d2484838715014c6bcb1ba39c124b1a09116d5f485c3f4e92575fe348c33e2437260b4162cd86eff01f418b56aebd6dc962cdb715de9f8c95ed9648e9d3adb1560826e9d9dc9354787c1296cb8bf5fcc6ad3d77cda2927887089806b5e970163b8102133dc8ea13a68c569a4f9216109a631c19a867c58022b3c8f54a885755978554d0ad49af894c8fe2526640a0008fbc3f334f0035f01d34ac010b720f617886590a9789a40ed209ffd8ac03f1c60152ead61a1fe17bfd082332cd057d0b97247e27508e15759ba7c9678da793697f293de4b6cce654ef7f4303a6b23a95dca1c9db3f35db9a79b88b0a4b535ec292efcbbe966b9cab738098de39b78451bf31148e24b05631f9a224f78e9628ac68056422745d060f21ace0b327132f09e9f7675ea32b7aa6056c54a0d78e96e4125291e0ca1338c391c38522a9d6cc8baa1d341168cd1db5b8e2f9884636e2dd306a55dc62e13be8e41f8528d2e3ff35222362a12a9b50f5bd506ece05156144277a8c0ad20398dbe6bfe7dda896013030c860c22505f6a025425fdcb3c1beed5a89b6d14e75a7217e394696de465c89366a5c9e17d0a4faf9df406bc9cc5001e11ab816a6df279763c6e6f2298a9bf8c0e5dd43624e3abdc1dc69d61b54952b81c361dea32e202308057238f4c637b10cd40d0c769bba2cdb0e08ee11afe432088b11f93a8b258ddc5c2ec168b196d2b8b44c235b38150afbcd211a9584846f8b532423147200527d25034af71d846c4ead1ab43eb0db5451666fb3bdb45bd64c4f31a26dc83b4542f29d3f8b78c0d987e3c291a459f2c17c4281e4ab3031953508f7f9d3fa63eff23fdbeef804f44029c84e80f366b7eb4fbb6c9f653fa6e7d31eab2ba4c5105414625490be0707f30fd3e5d5ff2ad83e86a619db512876ea9089683b6a03b530b8e4391a2d742fdad119fa25aec2b9b17605ae0825b444b00ae89943e34f404b4398334f6b8dd870565f2917e6b3073a22d6aa5b796051f62fb7748ba81caa1f5154eb5312e9132d2c2d850a2106a6cc134357e0395d2dad379e6f5dfb08edca29e4b3ac445fdc5f53d6d32fd92ecbfede0f01ba8f8f6684d0b889039cbca12c6ed395dfd9db223c75fa6e1a92b7bbb41edcd7c795d8386af93023af4a3d0b1d040702611a2768b778cd46823729746e09f212aeb16245bf3685306dcfee1c51b1338b87dffeac464a88e61ddfc118a954bcd2ca3a7a4ed89fc2056d4fe2981d507a62b5f7d28e201487fdf2e64cdc08c102120d13703d447b974ccdbbee6c3f57dcca6c16af37e725e08230de804ff6bca0b2ad6b7fe098414d773f717a535fd7a0c1cc09f5d8b067ee87aca9371451a0ca402b8453a2a3aa387984a48c41dd55b53c966516f7bf4da38474768ba4afb25797076388899520a95c32a583ae5f6fa8e24d0cba068a075d22e47097c569745a25d4ad48ef91fb843a65488854baf011b914b68971c9506cf9e37553a2916e0549b7d75bec6667d0e9386f12d38e6578ef191a2def821f0d8a58d2585029192f0459f2fbe5e5dd80c24f23142912ace6636c44c47ea9496bccde75ac8dc19c493f6673908afee0dfd024758998b625aca56093f2835830121ed40c111cecec03949c24f32ef015e7712a9a5741a77b33218117d35a7fc3e07b6bca2d6d5d4528f58b1f9db2b1ab83af9b1b1a05bcf4921549a601ddc2a48f01942e3939ff631cdceb213c0f2fc73ebf14434770b384ad89a1e28ee917cb24f39835363233d5d9c10f3d7dfe9e67a254b800cfaa80b07e8685f370c8c4baa58462c144061d8788e0c205b84a333cb926da404304f9965c3c26944113662cca762a5045af64ca1b3ef519201e09915e0b5d0d233a12a0d076b0340b76fc5ee6da711b2224f21aea205849422c99ffb7ca50a2407b7620d55f175e12fe987ed9b4bdb1158aebb24ab5138961dee07571c085fd73a4cc4a3fdf634b50caa8c2306623c5dcceaf807cd0a5d0efd1b30718c225eb01ee9711af8cd2136a43578f3f5f1c8c1342651bb3c74415cf878e6c930cb35e71e7dd83a5d0f342490470f1fbc22c97709c42beef916affe6e0539452e8b5e36a090c0c55a619c36ebae8ab89a38893b0527b0a6f7ba6f636433e1354889655e92eab235af416d835020c87827c1a0ac7babe37ba4d4c379c2ccf2bfb047a6baad5f0a7acf8a6f7112c628e43ea634668594a87a13b15515a9f9ca384b15eddc78d77e557163d8e97b9de8a80924169b5814845962bb1c28874d259f78d1a87f16aa23b628bc2505256f09ab03a0508a97ba9dba209f227ef63f1e03e6c607729972efefe6181fd4d6b3b49f47c12de8378f7dacfa229bc2e2117b323f9b518cce0d69b350ee72e68f98fd4a9d8381cc2f330259fac4eb05ce6a486020c1f42d7e533cb1984f70c1fb0e1d3166a7e1b0904f5b10f170114f001ac820e96d521d6cb7df41e23a7e15df75a2761861a4ffb4c3b3b4d906841254ca356f5cae1f3b15ae5f2ab553f0c34dab73c1b717c0d6b9c1cb983375e113db41d766a35bdde6f9bb1ab8e00a9a1dc0960b98ca469a3c4346e26de8b3425586c9cea7edd79192dc6351a7d4f30fb11819f81c03a43a5fd4260b30d08c0100e6f67fd068cbb116acdafc0a7f629e2ec78fcbca1ebcbc181599502d77524d7e68d22ec4b59721796f184723d498867784f6684f02d2610f4d7a38e01e126a76c25f72f1a3d0036a206dc630bf58d3f1cfc7b98b670f24fa5fd3d0c23720078bcabdb4178c511639cfbf6f472b320081a2de09b93b80285264c978ffa069feb8783ffaf1787efda672edd5ee7e0c41d8ed5d0c01433eab87748bc0986283c7730157ea775bd0661f706b3c980ce77e28001bad6edc6cc0bce662075475526f304aca3c99dea1b0b6ef7483be7957e990253b4b8b37e3fbbd01e2cab36c60f0a5b860068795a4a010a88a09929069f081e27ae8b3f19c020fe3d56dc5d8579c703b67399eae88169a13767abf8c06b4c6f511ada7a4525bc3ed28a6f80996b2e65676cd2b8cabf9c6ed4a8fbc0bd5e77b3e42506e98422425eadda63898befe47df9a2387e11abc721ff501dbad7e6e242c7bd6980cfbbf01cecce575ce46c552c44847dd324fb0bd3e96b9d38dd67e992d02d3e71cce439a4e90912faf4c4bd91380e38d4a17544d1451b994d68cffe6ba69597a27e5b7e7e7abe7ff5c8f46200fd6fa7f87948195e7d2a549fdde0bdb08a73388054b51c21a81fc4ea572c6ba8a9fb89af54a4773fa8e2a86fd973b774ab2727d567746b416b3a59b8d3ea6fd0dce03a18aafef864f3b8d26390d7d34312f685abb1012c4e696a2ad3df84ca27f8d8ffd0026df06931130198fbdd3f99a6bfbb4950f5faaf629e913469217476ce8eba3a38737984343e9ec67f5d88f1f55698b588d68ff9bd598295acc7e60411f4116219a5c0059e54b7c42938f386c51ba0b86ea54383c90fcffc9bcdb17f8b904ec0269b6dcebefcaf1389d07aaa941ef524c32cd747bc7b3efd8d3ad1576c6757625b643bac15ca75374e09208f2f875cee5e04ac91720d1e2336372c4ffc2d57563bacf064c93ade5c3f0891f364667a2c46e2b82de99f645acb894aea6801da62c3148cccac14507dd946ac871d7ed5ebe1c8a3e7e16f4b3552ea21d26711c5fdd0ff8d6a17e02cc422fe1abeda8324ab34d2c3410ec34cfb4b2d8608bbec46257e6dab8663f2e22ed00a043fae5d1a65bed70c79d9696e0b7c6065e1b931cec17b72dab07356afec3147501fe3ea95107e9239abb642e2d3a88d09b396e7496a0a8c5e7e48ce481b9e9c2bc7f33f397814f81bf7d25a22d393564900edf86f85bb0899a18a03fff4299ffb1d42e78f1ba1a063907c0a067e48b15769b9981ae2fbda2f137909afeac8b461e7fccb8a20838010ba67b5f95f4fc7b83dd0a22bc8211bfac660d935e619c4eedc45517ae1a123a3eda1b117e84e6e26b5dac70f2b1408a4952d84940a7aea3d17bb520bb3cbbeabea25e5aef7fb638c953bcf9d4745b2cb0538cab355c394ec060e6e30e0f40deac34c6b39cc9b6cc3a932381b1b743a9806b95bda73228fdf2087b0dbed39700b6219002bcc26132db8841b303d6ba9fbcc3ef77f17ca7ee887fecccc72c426c67addfe0b6acb4372516e78d9f1a00c8895236ae2205c51d26804d70372027604aaaf8126ee7b57601601f262c9fd204b8d634142662abda2239821036048b507f0eb7e6cbf9b28a8fc4d959af6520356032a00ad495d2c24cf1c2efb18707340133271c061b98285d44b39963e71e3de06f1b32276a3fc7990e7db64e0d0b41dfe8c5e241c011985775d5ff8a2980a8f2604368898317d37ade29c907cc4f44f65c54f2ce731c44760d2f77336992bc3a0a5074bb69926a4edf474f4485b8d4ded064ab296783a7052992f481b83474c1529a2c3ce78ee2ce513fe5ffe5b3965029152e441451a9973f7476ddedba15c9ec62ae1e5cdaa28d43207850fe60db48ee1d178c3ac43ad46312f509d550fe5972d9348774af6b89d3791753f1ba6191c5e22054c310a4c3223d9089da8138e2c7a7216962e80fe3f2feb39ae061930fbc689207d48adbb0eab23465f4255d849272d41bf4f7ecfc413cfb3dcfe396a12d10557502ef41f30366cfcbefbad0d4b5a53067b5febd74d6559eed154f42ca357c9dede7d4b6690ccf5235ff41ef22840649d60cf69dde321240180fc017cead2250a78df0b82579b2ca0e22287707a56750e8106992f3a6cb5cb33df45cb047655f1813699bf560cd19fb003710ba801fe6d5855d4b09723a53d7ae95d26801816551e5d9bed3afcd9da2c298cdfe421b79f877e949ea07c144e2f816a440dd0bfa91209c2e6a264749527e003782565982ecd27f8452b52f873e5ee998dd43c0269e382ffa70929e34374f0a46238230bfdd1cc14cdd2994f6ecf81c7fb1ba189982c529b5136b508ef28d2c5e563e2ea7f41faa94198768fd6b7b4666e8de326567abc5f0a732ce9fdafd869c672ef6986400aa17f0fdcfb2084ccdc14cebfb4d65c710689be9b76558436baa8383ae0e27bcd1f3ae737d48ca4ce594e1dcf535c3a5a66d1d9d666efaa3b63deeb7f08dd6a8c8488d163302cbc84459a254a4377e721e9ead92b0b703e338470174ddd66e0c6fe09871313a8380682b3c01d329a454a4641cc75a35c68195496ce1125f35062862ba0e5ba4fa4eb91bf832ecc185d9e880706eaa9ad62444875581922941d954c1705c7f31fafbd9f8c9d84354747b99c24592e81beb275bd692ed73b081f90d1fb704f8c62ea02e8b06f84f4cc9800999da15cbfd158d2af4137f93a4bcb9e5dfbb1d35acfec838b6ffa7ca3982349e4a2c74108e8a6f13f00d1e47e223f4e0117898fecd5131f957ef85f1325aaaa1eb30a8360c66b507cc05953f16ad8d4c01f969faa34274726c741fa14bbc51dac9843e2916e852b8d5e4f3116f0aa59e7fc6f6a04bc554178a3ed7ae332948066b01cfc1dd89497a25db390f17e65a46060490b0fbc2e6284cd43919ac35da5119e3da85ab5c70c891e39e20373e479a4a1312d24097565d1123284dc96710606d07ed652ff6fc88763bf259ebb8c8742f1c9ca5d030252cf181b0ea5dc705b9742420a8d3b4fed69c5bda8612096fd6c2fa3f8f3b5ad099062530bc3f7fd04c99bfa9506c036da42b82302fe93b3ce3c7d1b97c5d8311507e37ccbbb087015aea89b3907bc4a16f7151542180f46b59ed61393d22480438ff16b3dc5eaa95a02eb73f9490df64696a2b289828278c46a7b23e2d5b9fdd94e4c49d684e1067de43d9b3831bf1a7f2af21c98190dc51659f807172e7647c3fe752755e360719330bf96f2e9be04d2b308d3a6a20adcaf5dca90905d94af9426fafbcc3b75d5d38cf960b5827b1c4d944c87e17beb494224b7942f22a5bdb55afd0224c855274158311321a9097e42822011bff86d72438fe025fa5a751ac442e9aeddb42c0807a3b6ac77755d7b4ef122115cc8bc6064774be18b3fa0344aa235d82d4b1e3d76300e3f619a2b13ea69ca0cc04a2e696dbeec296674c12a6fefeacde8682271039afdd6f22a11911f7ea8a","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"779b78f0b0e284ba3ac14be43b73028c"};

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
