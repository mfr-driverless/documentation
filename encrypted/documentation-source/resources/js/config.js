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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"025b2db5b594320513a9b95cedfaadc05c05d96519d6e261ed890aa6772efed94e437ada528a216f870eccdf23bb0d8cda524b147a035f7e1c700c5d1d042cd4a85f360b80ac5ceb0a1919817885013f8b020385f94e4290b933a4dcd6a299b3df0d5ce826bf505f560cb7273d32d250373cb6e689b032492ae959a9da76fc11bb78bc8358d933fcc279b23feb0a8a1194bbb753678ca25eeec4fa0c02cbeaaccbe3b339e4690a8c70c32714db6ea17084932c9e2831f51ac5be3d54712aba8079f706c0b9c9b222d5dc3605b93bcc23f54e98cf64d3d44343fa737d9e7023527cd2269e3d5382187da8597a0cba773b808930e24acbb31c68021753ccee35471d64a84badb691ff69d60cba77ff0f1411b7bc3ef30cc90441c4b1b6481efe7e8f8834023ae867c18a770e10e1c5150e46e494dbbc3a369994b52bd8fae093ed936d794fff3742f341a562141f8fcfae8169d33b63a2f541bfaee8a71bf846d573006dc77fce5cccb45e72e3674890233e811e8c64317f50f33cda09425ff8439ef61aa818d162d03c3a970447fb7f19e61a9a16e5ee2b7de94d9139f40ef42f91002626762fbb6ec70831b3e20e5ec219dc9c80fc1ca09604f04a335c8c0acb43c5b944bd024c41197d770bf1807c6c2d2938ddc30f3c12d4d9db4a14b109530ad5f47c8151d4bae9ac520a33872aab20dd743fdb7d91ab1ae414c11097372339e71a25acd4d187eaeb0a9c467cbe3cfda5110c726f1d2264edea087cf202cdf58aa8ad7eeb7142ba22378c47dc16f8344c1d9e09dad957c72d302d3270a6da8c12c8e680f919c5a58a52d5386092c8c6453edad95bce9eb3d0d3cfae64a87c02e77c64cc6219795d12ef31413323dad2551f1fbfa490a62906958e94301f79a6829ce3fc23f102ca4c2fa67fb731a04261fa32b535e88da82de3c1854be0e65d133f33d3c60ddcfc0ab94c22905cb9fe458bc454669b728d7a09aa6083c754114b21b5f6e3e647b3535b8b2189693d4677575ed534f346093398dd0dd177fae8b5d0f60055084576b25143ded8294006e686b53df6e8f607e6b7a0d227ad01456079c7b6f1bd6db0423db5cfb5e1e19fbf8b27df2b44d49f887a7a3145826beb057aee02fe618d62013936c705cbd880ba368ab5c601c26a5f362e18e043c1394e51c140093967479e3f7b34de97129506f6922f1bf22961ae3f2a40a29d878641f2c7f11638ca74a0e6a9dfa423e9f0e5100df2006ca670559ab4060b27a2760de489ac980723d885cb9f9cf670bf1c7da741f5db9f676aff6822019dfc4c5d65024aa1d324875da1f3d789dbd12d83716b8f88da6ac265735219ebd17674f8bf48ccbd9a8f33af513972121eb696647d48c2cb72535a5940555b4afe1bd9f02eac2edee6ef3344d95f1355eed64f9dbe974c76af80cea0a40b4311c5b38b3918a8df7226585b58a4babe05ded2dd84944ab8407864e623e1fcccf0df4610943d7d92e062250cfe6c599fad738cc5e98fef1b027f0337b716e41f681d3538cf85efe29a49f400cb08c09ea0ca0eace387c4f5b338f783f5d8dd4d0d9a7d0d079f721df78fd0afd2a51cc2430a1e0ed42efda60acad95ca0cd9200b47e6490c04d69bd5d4d0498942e8b4d08d2a7425df32c93b12b40545a0c82a203e50d1855c133ce648bab8db16fcce883390cf698909aff8bfe6cdc5189b4979425446a86b38bd9e61a1e4019844451fe34eda31f0b5c45a6fc189b91ff6b4629f760217da96a82bb8c86d17f0cf7aa64de589b7ae4307607b5ef46b3226675da27f7a3e35ed926e45ef943b31a391bcb877aa47a0a077388a83d59c1aa649a73b7f12e335f0514cca5f9fa40846cd81c5f85afa5e3d0f33c1c7b3d89ca42cf946d91b4b3570c40722a67fe2e28bb7d5996f1621741b5b88ffd54a5a5ffc2f83f14904a2d4d509a0d7b46c8dcb43d7f1c36bee6fed12643b0c23be2ce6542fb45d61f6f3264364981ea46592d8240b90d40e15d9af70f6af8e8f9eac4f03675977922453565d74a2fa0dfb2300704cdf53dc4873a05c8ca7ea195beae5f7d9fa50a446bf27e2f8be7f236271bbd035a5fa3b184d3abebc1b8b3681e28dfa6d5d22024e5bf1a06b3ebb933f4a3ff6d36da217f2e38f8d12b364c7243cbaa42db8df1c3e529a7f933f0779b5eed0d6d05f509180deb546682a22c9c5138ebddb5b2ee7274f4d8ebc978cae3df3afbed7d991c177c26df74c991f5654da950840b3d12618b6ebfdced6c0e5fab2da4b617f79abfb0de2c07944f508aa4a81dc39443cd59093dc945d31b7e33624d2344859e507420bf7ae90f2a3644a978bbcfe29b00c091fd8d7faa5deb0d40e59ef31fde7358c80488b695678fcc67870b27cdf4b1180404931f0323083aef1a1464b945a481703789693368b63f41f6598a0ac872488edd0ee817cde630230acfd8d6438c5fef39887729e443211aaebadf61aaa6d0fcc8336fc6f8445129f8eef142501554f20f6da04a838a82a7c0593a5c24894b0ff3ccee7becad740704c4259bfb24ab50c6b58d330a6c861c99203a1be210433a334388a577659347332e6d37277a53a3fff6af90ec954e2087b3027a4497048e1f178b001e83d9eed21c1372d5fb2647dc73a1ba36289c4ddd2f16178783dbbf517595bbbff1cda12d0559139e9565c7f39b55376e38b864fe8ee2b7fa71a6bb09c1e33c7e4a747f146c49dce6ba8990c0240efd56397c70a7ddbe537dced508cb457aa9fa18508c17e1fbf887feca6df7876b66a3cf79b1cf93aefbfb13680d69db4a41b2b9a1787049eb52ea77c6d600419a2539187eca7a887d1360cdb038fef05b108019a170e31efde7cf40b779b49b97119e699e8b51e031074f08e4f435ea0b15f8dcded0a0694018fb96a6902c7248b15f17c1499459dd0d1bdc4a59daf87a5d4a3b72832eea0057fa994b56e5fad80dc47162af1732593be54f4de1d288e9e01fa199f61d0b3caeafb7033289b4fb606555808693612bc177977cb973a9bd72f32b81fb2d6fdf0a20d1cb1f1600f0f2ba219901b48ee0805d9135f827478a23ed4b27912a4fe2518f7058478cef461b61ff429e3193d2d7ac7edca383b2c6b65c0a4b6bdc6ecaae641a497f4bf04c405e92421d82ab92a5a1ed645bdc306ad54dc008c79197e4ef959e720fae396e766605a706560bd26d7a6007e22518948acce5b188c82bc4dce72bc0b766ad1a20e38ae1f836fa7d3c5fbc3e5321eb470e804a3e8ff848fc75eeca4fd563ed5e9955355a7e72f0c5d3a10e8984516902d6454ebebe41209fd2e4873550081857294b9f24c6855cc1fe5cf185afbc7c2dda382f09cd246e449732d13070f75fd6977fdb6fed1af7993af52429e34c23ec284ad38c416866e81cae73b72f4b10a1c35b4b8e6e80b06408f4344ecbc394c2270c69df84b77e10200afb5a44dc78604ba3a0ea954a8df6a2ed8d76f6f6ae44c7f78314554a7301b6bd0ba247ed226c41890b493e39684ca162fcf29fd24abe04c18ca30d7925f48ca020cba6279c1f60cbc8c7e65598319b7cc46fb6925c523574e2bdc45bfb06f2c641cbdf0609b9bb06d1ac1b9ebba257e52158ba47f7149656f4e8a1fe251809856a681899ff4a594767ede135eb5cc6501003ed1447e46d7b5de61179a075ddbfc40bd38048abf0c2c289a3d3431da8a224528ebd646978cfc126e3afe450cada8316d55adc7dabda0252892ef4edf87636ac6a6ca5ef61b0ba83d2337396daaab01d6accf93b78ed37864aa9f275f53ae3f598278c4df2a3821245a17b1de839e5cf0ce27a6dd6b6e01f8745619f2436d251937837b0f32b2a568f28227f36fed096afea641b7601821dfbb0af0d9eace6d808d498f3e0e8bc722a5ad86054b595c5d714d4f04cdcdf898512dc18548aa03dd2cc7386974cad8093e411922253bb998ea14e62402c304246d6e7f644b541f21ec19c81279983ab46c168d1e72158eb9d1b77d9169b6116af3eeca001a11bd10ea2fff9b9ade94e5abd66770bec27cf1a3db789910a674558ad76c4bf291fb5da3946376108830bd4237aba70112e361c2faac7a5920b67b6f0e60e909dead93adcdc43eeed31f9ba56c08afa6a8a2b32bae8f5e1b690396a4d468d0c3d751e9f5d30260557839772cef29d136c3c46f10796330025e57f13e82849b437c529bf0a96b8bc86a3c0535a5c9b90cae1818fd93eb12878f649c3df98ce3132c66e132865cad4e62deaa3be1173ff0db390a3e8c7f26f8abc1ce1e0f234cf49a9251177555103ab98b2879304e2ad627d8e3608efc0d0e7a24003b858f1d4c581053b4bf23b3eca482a8897b5e30533d7cfac82e136f504fc9a13f58173bbfcd91c906176590e179fbba9dfa4adbcd009d4559275fae16ef884f2018c63bf45d1222ac635f6cba2e8b3411dfa51ba6e94ba240320f43fbec9eb6c69e7c7bc31c8155e921d5b76a5d0ad828062ee9bf1aa60fb925dac448d69cc22aef45807507ebdad164563823a878d6f310a0848838c70db066529b8b366f71484fa896831cfb4e120152c820efc0d5c497a34394b373f8393ac84a15e2bd0c6e324f6579d314ff28591ac5709cac04324880438ab7d193ce1e3c996463565bc2bb4f28565637068b0f65e73818593158bc391c7e7042446ab33c5a0cea06cba0cc93a66d9218524437b73704a5473e9ebf1d2446a8f81c8389cf1d9b0d6e44e5962af97e54b69c8ecea1570fcf77308385492ea7ad7bce227095e3f5a3234b3e70c7c8fa89820e47457c284e5768f7ecd6e1d64d60b527083cac5fbc9a63035d2fe860d8c0f15c4f6bae87a0a38cb2dbec2edd352067922cbab7eceec66aa8dc81e3ed779988f44084567867decd0d06164d45d9472ab0714eca14a00d98d6e60b05029b2b99db324268f4c752c19066d5ffb97c569003554b902cb9d95eca073b6dd8e1387519eec16dac29737fe484deba34fba618af572baea941e440f2cc64384fb7148f919e21c15f99ee123ce7bcdbbdc8ed52ddb0105454a91d0c77b395c60514c04f3bd1b8397d72efd2c8aea57d90788bae176cb788204d205f7a0d8ad60a6499ce0d35612dd0ca014330f5759892b8f6f817b0c1b97250ab297adfccffbb99eaf4b52002ea650164cfba84bf3bfab34d3cc23737369430efa3711302bab127e8f0d631fd9de972ab832a8e55fb92f9f1d03213222217c1d409969cf49b79fe34d84b69e78f8b023f98b841b58f2d6a0422eeb8f4b10f0e35b06a4a19db88d6f99f76c3fcce741c231bd277a69e8bd54d55b800a895a79919164d695439cd3f13f35979d16b62da02c0466410b8c746af54de5038cccde3059fba1f8e89d6c2353b5877e696887f1dbb77c4a640f33639cc224a558881fdb7b7a0e44109ea895ec46e441424f5c2b11b1854c8f9dc9b5097a8cf4819fcb463b4e36b676efe3ec2005ea67570710e939aa085bed0e9621ce77602b88c9a0dee873dbe40e0d7091cb0624bc4f7c0be45665f1d0d856d43139747f9e3f260a59b7eef36d8c4c1bd337fe9309706d32f40b758b44d5aef9608252ffef653a46f0e4af7d36c5414bb656c62db67e6af52c94787ee2dbe21e86a6d0f243d5620f0e5b06a6410258f53ef6f88c3ee7a6c4360de922c79249a746383907b9ec3eea11f41a982e165000526dcf5a45dbb1c25e5f2de3a2efd7ab6a7930771b66cd4b67a1be8edcc27eec4c80ff5c2245b27a2b01a6e7c9fc76473aa9b4af75c2152e50de748ad1a66e49fb00aadda7c2bfae51ab4d5342176bf156d4a4c4b2317a12ebcd8f5697d85706c34b7e291f0e6110e826787dcfa37cd30f67c77948d31825d91c5f4390a3bb21d25c5fa34ac402e1517dfdd3ded8290fa60d2cc2f6abcf2a8da48c5dff8d519e75942a7987eedd9300217ba5a6f0540da0aa571ace3b681351a3c7eb64dc8b9f18e6bc455eb6f9ed2719d1cd813b8c849c05ad7d8f24fd543c1f02b39073a4ff55604ea01f65670634a55cd06c3d54a8a819df2c6419f543a7aa25d60ebf750f1e96bb188f2834e447d299e201e603f67109f719d49e58a88c03a27338bae12bb0f9601fde2bc0f34bb39d852b3855d80562df9264182b09f54aaeff3e1e4d1f2f500bf5a388b2b5f6de8d75d9f09cddae05d142499f426b27ffb9aaf29773dbeb3afb5e1b2fd7918b7caf733b294dac7eff1b44b4c72b6d6cfe902fbce4c982b5c126caf25f2e4bc614a3574717dde6ad574edb291c554d5afd54618adee10d57e30a2c1ca494fb04c8c07e8331d49ec074e774e470bd87df0da6e04a2b49b7afa9a860ffa1f272ddc4955320b33ef0eea6e2d342515806a77b66760adf4ec463773437a6b6e80e6e060d8a4948d5b7dfddfbd41ca47779c00c7614a59de09ee5a08ee38c96a304c36659768d990fc6f660a18a53fecbc0544e4f440a875bd9b1f8907e048fb7becdf862278dcee56588046aa979413cab4723a13fd98f868b2e1e6886c948b2ad7cedf854e24ded216327e1bd106b271131e637fc58a4fc9aac1398ad7a61773095948bf2fa74bc3e3a626b80c3c1146e1d5a03f9b424ceab5e018d95ab45e18c19cc9a9223de9779939a05e67e4ba9640a3e060bb20b094b8704b4e44c7ad0bf0793cedca338476b9e773d037dc4bafcf3b3f9d5479049cc27f380f3e85cae06e5fe4557af33bf5832c3db2a3898d382adec129e51ffe4f6bdad20c8c8e768f522443c5fba610d2a83f2928b676e6d059934278143e261d1d168f99852bf4becf8e92ba911e30dd822fd5548fc78b02abbcba2fd7194dcc0fbf1b46a812e4b57c444177563b39e14478af7486ec5931eccb9df4e4f2900317309e97989cc0f882ebd4b8cb4449a30e9a56338f9068522337125c39c485c9198fa04281b23b4bf62b6b2f91095b593ae8d29f6255f2feb2af86c76c981d4e6274ebccf28e5dd6e9c64694079dbda317b6bbca29e2ac39883d228bb96914e8d7c05b3f7d1dbbebf5feb48d8505395d76be6d38170d8c2feb4dc4b8eb674443ef9c49bf46eaf5fe0b0b59d618048df5ac58c0a1c3e1e5160d52c7c5c13585bc20538c5d4972a7602b21678945937585067aefac0b89775a576ef15146110b674b6b56173350d977d6cd0177b83a1678ff3a47869b171176719c1d80dcf4441b8ecdd409362278d23363aeb89cf39db0893c5ab1ef1f01e50580263bb69a56b9c8d627783485444f4b444a916804887fe4366761ed508b85b14f338f9bb8dd5b7863a7389bef3f3bd85c3c5fb3f56eb140b61efa3f5502df161b2d84ed069526b2f21e5c3e9b16c1f45de6d0ed48c7842742e4ce8d4e15325ba0ba36d8b7602145597f3df95fb54de14d662f56e13d19943a276e0104fa182f5b7b946d9b393bc93f7905a6e8fcc9195854c4652a88117ad161e81e362618655f304aa2f0d7758e66673d34b39f191c6517a0175dede3c717eff7e9d02a54a04789443758e67841f30fabde655f1097e95f5101f5d7dd7d9f8fbf017b852da9c47c2a62ab24ad2cbd971916eb703eef34c44f8855bb99f8df1af2b804e97f080e778fec8bedf1f140381febdeaf7580037585e56490b67aa4b1859eab72cf30c841293ec1064323afdd0146662b6aea9e152ed7c843c317dbb7463d7e82ace83e816c444d303f6f6104e11cb5cb6fc19869efd8379cc023fb6b1fa137d8a6eefc4c68ea30091d19c362864fd26917a073a49d88a3d8675dd40d7418d58715523b71eaedfa8394bf95f9bc791600dc5589cad93c671408f7b0c93ee36d717f666007ea5629e0885fd0f32f2c1aa08add53526ad66e3018c0511835ac7676e951a5d994aff5b441da1d28d38e31c4ffaba44b879a0f0a950b05d986b03a164f367275d11b14921eb6e00fe39b0aa8e19f32a959429da2dec44010e819b094c3d911a9e976fcab0f9859baf56a4314030da317bb56e3f280210fd72db89ec9da7b195a02510be46db7a61d1d4911d6e44c5f96cd5261650e1c5f6bed2e29654ec9e9186cc92de511f78a456f126377b1f99d28cc83e90c9a69106059d4af4b3279cd309db49baeef49b1fbdddce9b78db1ab1d330d1717d796a4dd203d54d66a64ec34ca52de4e0de7b3ea26cd4e4931c34f6a26f7b809ca9628343bd840b7cbb86c06b135ac6e22b3dc218a419f2b707a27c25695ed5f57d4d3ab7950fb0a420ee2ea8253bc047c9c9c7bdf03b704c38ba04afe6800a40e40d3ee80025789170a78872238feeb0ca51f901ee296c29979edaefdbceaef0a9331765b4fc778b14ed1dd008b4fbb3b6909c4c09e9fc263a8f98e9941e96aab91a1ebe8061e3795f07b345060c55c10b580b441c979b4c8e469bf0b0e3ce1174465ae0622e80daaa817f958254411283ed428a06e8fab60364109641af6284841c48d8035645cac87e25f06bceb5564df2a328afb845d49234db9e54d073aeb872d692444c45c83f4f108e2a601d5c89f64118279938deb3997efbede48303072343b1417bd3368e8bfc9ee1fbb1bb4ac3aac2bca980208266b8050b2fa1d079ec9ad856fc04e38d8deda98f823561e95a72392bdd5522cd21afcca6beec9c913dae617e14255db3659f139aa7e8402b36aac27ad662b6d8e9050a2146e56e0d4f00d229374a2228a92898f80e61df2b144adc71e06d216624a9504355273526ba36d281c460a440038d3ff1d7e90e2d1d51d4aeb3d52b7e5d50f11bd7def7ab2f4b3e62db74b6dca4758daf12883cfc59b4332ac872c76a4eae42663886f93694b93dcd566f7aef9a0621c6a2939f31eca63df6ba4ac1f9b35d846a70ff1fb340afd6022ff14ba97485cd58755133eac31d707224fcb080cc5b03916dd067a15aefa3b242d7203a9d46c6b94406a61bd491637916640e2bd5ed9082f81bf19ab285ee9104ed32654b58e7a091af44089401c1a46f0d1c147180516fa588b38d6c8a2f7bfa57c209701d6a7a876dba834a040daeab3b5adc710f89a62c8dccd49f09fd729ade9cc07770e8ad072c8aace59cb561688a6e215adeaa60d6975721c2a7bb8142bd0592ca688ac0b21faca2d1880e58c9562615732fad2e432fa957479091dd04492df8beb9805b5b3f3d93aa3d5875bc99cb37990b6b51422ffddf0bc2066f208f3ab92022ed0a1937f6e1cd0c46678b3f447e954d44b6d555cef65eaf669edd31cf4b6c08ff65614c6f415abcf406013286d4fcb95d08e016f66d8135d7e3443282ab0280550d0f16ca0b5614b1f069f8395e7227ec901e89ace3743079b845d10f076b87556432956532c012308cc578b225782924060022303d86015a689e601193772170a1476b13dbe93e49340d6c6b5ceb1890b9b35dbbe2188e04b82b15a3125591f58f7927c8396259d5c7f03a745248f28141295efefb5b1c79680cb89da6e305483e0708cde914eaba91f565c91e78fa01b06e53db738e20360d1e05b3dc60579619bb45156be5b734abc4c9b1cdfc592fd211b73a63aca0feb60ff2e94cc0e0bc140eeefe9f93c12656199b4695c330bddef57b78f3f38bdae0c8c155a048b76475e3df16cb6277639f0c1bdd9a5b168192895082f830f2ba64765c2a6d543df14bebc69a55cdf261d7cc5753e8ddeee7ea8d7c189f715184f33713836884c81cbb8815b58cadb1db78db1fef468628175541ba9f8e00dab2205324fbc5c99320720766c34acf45c2f113544aab96ab4f8989e9fa285f869de14b47e8e48244f294d6f69f9b84ab0700e7cc3f55f4ece9dd6a6f3fbb6c71a2d525f117fcc539dc80db72105973982c14c82de9c0f2de612a4e6511947e0c39e788407945645b60b12b8c939ec078fcd6a7c1e59d26de015a9b10212be2d268555b4f296b44f716100ec49fe5f92ace60751fefe01b2862f8e63b8416606d48b526e4ca71bdc51b88818b37cf92a62fd5e3c037937421eeb43846daaed146635638c2725fb8e72b45ca55a2e58980c874ec56bc958967ac25f4037aff735b96e037bbbdeac9220e3b096c351a06ab84bdb64897535cdc445a6a4ca77293247c6537d5917fcfc697dc68db044a5e48ecc5471bff7379b47411bfb195a10c781bb179f24e211ac035e314b5e900da75a102115770eaf7f91dee0c5c34ac69186b701d58dccf64e6261843c7d235f6c212ef0fa22870fecf469e46412fb618c53c33f0b3a01fa6b05342202038bd3465d9d9ef5a0e953f0676e92d21fc8fc867f1ea89ca9766a0a8625c52624134f599e4cecbe795ff4775674764e83592f33246c12806e5230b0f0d5aaac80b05240c3b9d","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"8a01c5d3519b99bb5af51a466587a22b"};

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
