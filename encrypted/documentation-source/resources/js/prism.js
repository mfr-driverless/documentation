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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"a9645fb3b4f9d6add52a1c80019f006366db64e1a577d9ccbaac6f9e8c42468394035c337797687cd8fe782be8fef6900387cefaf608254bb16af7de7c6e3e904e3221ab9cb0047425f90c6b6554ab4e19111e466306aee7ecd65b04ec2bb437e93f2f6cce989b2a1dd65fadea5c25f4e17a0a72a8ad4c3b44f5a6bba545e9ccb28f14fa1ea50ba609abd5ae337ba577f11fb5c08549f72e97a3d13d920af64b50f110a7b2fbb1298cfff339358dad5760f2530868075b28ba9d09befbac9982a605115fb246b06f13521361a4148388298a7beeea5c49b976f62016e598e84deb296707db88de11efcadced3e1e887b29059f6fe884a5f20c1c4a2cedb64bfeb8a77f8124921bec41439d798b55b47947a7ae1bcac0bce867523871c21decfa59bb025e1ebb2317b88eca02b0645f4abacea6fb38bbff32a58b4d8e78c1cf51907260bcfee691e65ea0d660699f70f6ac22dbfba0572af5e5b59e2ad0effc1947f046bdda5d20690e62057eb7f16a1b15b81fa8d55c685f038c56d3245cccf7927c09c0fca158dd7e2e4744ef4d300daca82cb4198f2529d9fa69a183506dc3ba1d120d31b8af3c7b3dab291b8fb9d2a68803a6ecba2bdb47976447690d6b9bacc4ccd85898aa73381687c0f85465799673ac0e85ce5b2e283c66403fcccfaf403b414dea23c5cef13cf3ec4adcb844ca3b2478dfdaec66367aee17f7a96385471cecc043c2c779517c8d3585e2b6d9f23aa1de7c02ac010cd87f27c7b32518b70869693548dacfbccbac47ffc200493bb844bf33f8d4d17ebbd1bcda832956a2172d33f09b97297a7b56c5d3ae6724725e569d3e82c505d315a13a0905cc3dd2521e2cc4968788a6b48840b9567d70d8cc22fa200f9b96f4a9f69dd1cd3bc11a104adf2dbf71662f9c7a96ba8ce352b47148505474c53da8ccef81c796cb04e3030fa634054540c73afcbb37ffefbd98b818c93b646d2366236746818ec8b39451b5d89286cb1db4915aa4c38a6071b8e63c22537de0598c7c4ea10ba1f449755fda7353f003451e3a71058ed2e43344c7ee931a83a4d6f96e146e65315e0ae8be1d6802767aeaf3d685ea41b01e4cade226ae8c280b5d4823cd830364196cb24c9c55c9681752b1542d1edb97986a87e7a00d913e96264639acb2d5736002af6f28c90e8d28a4e031c0162abe6f52acc62445caf054172edf2ef7a85ac9f0fa6cde003d2bd42f014039c8612fce4bafe14f6e050a8894430bb283e780a08e7af6b5732c8336fad77c5e87bfe32a0f39207324e5b834c14f815b9625484927c24479585df94b6f8e78490570f8b57844641d6f90508756e3c7b8e1e4365303c120b572d9f2f5c51e9aee3700794455ab4982248d56806fd0d6867c428823404e0cf0c8e5d6939f1b528cca4af681916ca7582d083db397ac41239d47d473860a93406b13401174afcb3922eb52d1fbea54fbe44a62aa4ed688411d8aaf119c89ab5fd10b0a8f1cc7d2536265c47cf109a66d7d57c0b4877d05a2e1338589b1696a6dff0f527aa490fac8e42207a7c8f5876c8a7cc4f6393c06019a7d9ec11bb0460653b5962d56940bb9ca447112dbab85916570a40e2d3150c7fde0ca64debe8de25ff9c780c13e8f3c8a3f2b1888412f4a816b9a4dd2413519c9c44c0f38a5f2d1586e0151af544bf63db4278ae669fcb6b8826c3be324891d6550f6622f4cd3f284261d260b823a127238758aaeaf9b98c8a5f593cd31898c2ef1a7cf032cf53be0048cf5a97a3bb5a27232e6a592888b9f0ca901a5f8bd8b53c4d27aa357f97943fe1874d37ea4a927caf97e15ac5d84603cb6638172bf2ca9cf82df99a2f659b17316d4c662ca672744a3a773863fcca4603e219076c6984903702bfd1ac5e99c0cb5395a3e004721f561e6c64ca58f93e4281bec2b4f936854dce87f082ee3fc826a6e2da3af7aec608a33e99dbb3190172a1aefff5b81d159e0d77ad5f71f5bb68586764feba2dfda4fbfda9ec07c1b30887369ee17b9126867c663f0085d63602c0c83d04ea03fcca328f3873f75d3cd11d6f42bcab8003d11f52ab44ecb44a15c2a5f352eacc82d8793ec6d3db7486d31b94f391dbcb5f03788e58b09442a767ae6863a83cc8a5f60c222ea98bfec7aeaddaccbd89f706046a9da865af7455bfa4c5dd9543f39cf233a7bc2f7a0537590ea47484c3cea3889240182a43bb69bc851905514d8b7f09cb971776f0a5c3a03b3a395271ec09b0bb0c5bfaa8da0b87be1ca39faa659bff66147188e4aad4f2c7015bd65959782cec67aa9c1fddd2fbb230e2b76992b423548e9a9fc6fe70a76f29e9cc46403ee3b3e4b743a9e228cada59eee3bdca2421b0e3973fcabd0e0d2af0faa9ea2d6b05f105568a9d9bd315bf90cb6fe68f9c3e46069efcd546da9b0ceac7403df00fd4ffce9dafffa2435b548a5c820cdaac7fcd88a0f3bc1d4bd008f0e9c93cb86f879fbc6025e90015d4194e0c2e86cfc9b8cf40eda9577971a4a2026c6981404c039c1187c094dcda812a60051524b631aa68c90f9bc84c9df6300fd50805aca21d6c95dd286544679048e06a32ab9c5960c2df31ef8925f51171ee763411493668215e3195b648d3f2e40f9ca7408860218a253fa03d54de78a26148e995debce612fec5ec3732c0f9b6aff613cb12b8486e4bad2634165d9662a486fe14cb250c0de3ed6a1f5e71957c5e364eb11a9906a45cae07ad5e18c5d72acef7dbffcf6fb97710be8d6b5696317bbc27523f9ef945a3ad8d4a930709da0b26e1dfdfdc022f791f42c9d7829d32b1d866e0beb5141027e4a3f5f9475b77334edd4aba0707215cf33812cdc09d5ada9baa97f676a2248b390a751edf309e5a93259eff39c3e0d7f9cbfa274ac10812722378343485b9a06584f048d0b4c9d4b8ab5be77f38a3e0f4fa9011d9108aa6c08aff942f530071be79fdc71fe2593ba5db3b566e6b133782fbd83dfd5fda738c7d8e3b203d9e8df3a383aa92543c396bf868e6eca2059fbbc4e603ab5f96647bf3e15e7fe0a0d5f895560627e4be48ae00a287855912f148fbb989f54762faacdabd6781a5d7ef8c8e12441930591fea22288b6145199e28bf2713baeac624ceb65f8c38fe8d3e97ee29121460f4382517b47f6b09a42d07e3365ba688d929fdf94207a889e30e87f263d221d12ee086790672f37b205bc79cce4a520da71e389c55a38c9329fde1a6ba8daa8e00b29a4ab7b9f6f016d93181674bd2f492575fad4df098fdbc444126597c43988094213bb5b0d0308e0d2614c087dedf3f691e8448c10425410902c9b3d29884d54184bb857f57b518b0b30c24af213d639640229796f8b3396f3088bf1fa48dbb25339211e3a6eacc12b290a206d5a1ca0510b0aa178204a0a5fa348e01af5ee4aca0041335c762c5987083c22476ed3b64772ad9778418e3bed3316e63dbbe8a315c613ab5eeaf88649f3782a347e457b0ca3d6121e8c81c31b19232c65528c56421feeaef5b5cb1752bc8ffc515c29bc2cb6f529d269f18d9da9da2b26819a94509ccc11f9007c5e8a2bf3ec677d5763b1f6dc70e31c037a6a956242ceb52fa53c106367ad7cce3ac3dbe2e7ca51e49d1aa324176e3d64b99eca6ad79de61d3078ee54ec40865802effbc80941a8c2bb2698cbd53bf400869eb941a61784c9e462c310166934dd043f1539508cdd343a5218bc1616ded22e1585c109983a9d7c7a4ba95da9dd93eaeab808a59a9794b3534c2848d079a967536a87d7f226206a74b29589721754b9c4ee4861c8c9a0f5ba86f8f449ae66d158bfaee5f5255e5cdd4b8af161d3f40cfb78ab2d478b52eb57f350404f892e597dc5dcd9760dbb36a15318983be97da8669a8a6cba9f974bb550e66555572ec8e075f1f5eeb88efb9f786956ba24adde29b3156b531d00fe468fee2785f857c551470e8aa04f705fb78c2d3c1ef6a12a59ef0603c048aecc321bb17851812ceeec9350468de24e728c5428eb062006247fe54a4e1965ef4b31338bc3af1ac1cb333dc36575ee01540f446bf4be818af3f01f798c4692bf8ee803c0ce19c4b48688c4dc2d9d0a0a4b5387495a3d49a3b99ccde32ec64bdf0d15462f2739896286ab70cc69ecbf790f59233e3c60e8dee1f30eb6dbd8e6404cd39d89a269fb2f35167ac8039f87d0452e07c1022fa2f7ff6e9154f0f87621b75e3f1cc81bdb3b74e13f196c07a57a00f8dee0010a146d0ba895f9f4e233308a7b07edca351b7393907fc5e6f49e5dafca171fed928065d3abc05b8fa4f68d442d92fe74e90529257f2eff3f918c239dae16ad9e0ca6329e41cf46ec91bfc90f20794e83855e2b209dd029b5ddef8e034afdd3ac790d31336eeaaccd50f661320b96e7d82bb04be7ca97202062ac1796278d36e56596c3a44772b989abac556de86efb703a2e832ccf9fa776753c929f3ffa5e947a360da5c974c2e49c119daa24cc0f51a5caa4b93a51a371953e553637dfc16dec401040879d7c69f4e234fa6ff6f77e799fde39377dd8a2c5a753caf638d5848fcd164b01ace80f736ddb377985d1c42a3bf2f62d6525a71a07a4eddc3cfc8922755a64cf3afe81007b2d860cc5b3ea15a5a4407991454b60520007f570446d51f2ad9feaa010dc926d682538612075b9a7df44a8c2905914c1ff28774b461f2a801eae17d5948c6063a4143c2a4437f9129080c8d70c21658e5d1471f67a71c69043e605a808e229b1c11d3efb15dfe2a61806d638e82d9d408151c5133d03f943c9fe2efa37d043a4761c3fd37c0cf205c5177c683929de47c55892b0791de7583ddb3e07661dcc19f46dcf60f698eb91ac15732c766b28ded06c0e1f6a9f555c72fb55983ebfef9352cd056b999965d092f5faa4b956445992e3d8d468cd0fcded1b768ed4713d01678641a867b27b3486c648711f68b62980471dc3ef2fd7f96002874f77c5118b12d631732bdc77ef130092fdee816634b607f6fc313b2710be8b7e50ab1f425ab333a0f8ac42467d259ae7523e2dac7f3e3b220ae4978fc992cc31604990581abbda426ac005fcae6bd1a2b370875955c4466d4cab87195af2f74079c20bcdf731a8f9b37526f8761e57903d5209de5e62dd7432ce955709d59c36b1e9f8d29b7d4be8c694c2c5647619798ad39858354077f787e3ef2931e6de4f58b1c5bf3ab8dfc776d9fb046c6df030028eed109f6f4cf610d5568d1ea1a453abc0ca1103f5d5d6a667fdc21a18296f430c198c3bf8768b4d125b6ac06a243d64710d7b53650590a52a1a40fa5ab97307e63883a86bee108549acb5f0030d86966eddd6ec117b213d8c2a2004f6724de89e4d23c94648c427806de39492ac475c48af0b4751f65de3df953007104ce17f6c096e7db0f41f7740500e09fb58dea278d3cb8bf85fb6645f03a9186f9c99487280f0e18dfd1ff3dce7b7769f85cf0a6eed41e773ee0c3a60c4a5042b1cb34944c2886aca5a88415d13a5a332de043d28deb6e5a5a02dd7c0a457f067f224b6896a2949433509dd5c37464918ef89fb0a504ff15f875bf2cf408de5b8b7cce2ca16ff2ae7baa24f2d48bb1ad230a7886f2c379c89cde764a88a13d2a4f8ba228e7f209396afe11484447d401ca9ea9b36d152d529dc6ecf94b76125defdb417fc5ba17240017a3239efad0c130c46ed6f095c8c041e1036860f240a10727aa49a6ac3d793f1180d3a7152cdac33317b088cbf92f00db5506f494cc12004469a150c6cfebe3b4bfb90958445555c49ae70eebd26c89ccba2d9c3257bc8017694a86ef33e4cccfc31870a4fb3fed3ab9b6da6d7af7641b4c8fa037e885a2b0e0299c7992e31071165c1236eb63cfe1bb8c2aec3be6b9833336575b1cd84ae166747454c38171ef0bed32db450e59b54554fdc233faba73c195dec6f25f1905fa8c34d2ce02d5e57df86055a73e2f30748d78304be3342d8a863275932fcf3b13af59f1e50548f0b086dac2aa9743a91d9f5f964d92d67275f5ff704af5072cb20a95cf9e658aa96870cef4f8070f1648e4a89c64f0b98a75c7c9c3e1a22999b3dd5401fd137b34bd87a8e80d717baabf6116071bc04ac03610137cd11f15af8607ca02dc513484b595cf16a79a395dec30677ade1f5a926d3695efaca08ee53edc4043d9727f6f6240a2731183104bc05bc186b02a3f7c8a3a6b69e2df06e6619f7266eb368340b6204cc02a2769022083bd50071626931b906c3ea1a50fdf9400f0134ffacbf956eca5fe3ae6104d1c5a73996c716a6d74238e1bdfc5a58b682b9cd7d10b878d202e5b91d5b6a671e6a798d5f0e896430de5939c29a16270f68b9c42d7c69dae51b858d090d7946d4910241228bcced5d5e4fe07b46d16eb36ecf0fe3644db52a8596bc65897ded5aa44c734ee8adb30d20ddee304066ec3b101f0396624c524e85bf7304ee8a65995898b041eb1e284a5fcf5b47f94ff41e9f88cc9b70022ae7e141625f0f7622d2325aa2ecee634d81262dd25870c8c6657d702f627761fe6bec41b8fab4075f1efe419cf2a863b1a7a617bea3f2718d39ab022cda0f1742cc45b1d89ae0673a1a79e68c284a66297674778bd3885744e619e513abb44272e2c4de329f2f6b0d72f80e12aba42698c03777155a91898ec4b86dbce63aaf1e705b7992457610cef25b5711b288e10ba079b35e40acd1bf42b517f7dac9f3e64c9b1ce7bff20e4621cd910497afceed8febe874cf33d8340fc7104099667624557e99045345ed9d7366b3e395518b731f445c103789238d8b2aa41fdf2b3b438b3270838d0b21d18c7fdeae7c2552b9a1878b26b5868554f6ab9007471796d159bbf22eff50b844a61c9a5670805bb013122aa5eabc85b10cb35ae11be0424c4ac7af6a1689803be264037d56be51a4c67b10f7371a5fdae0e4ece6ea9f25d7aa1dc0a42bae2dcd00b479c0d5bafd732fd2b7bdecc5d8b325a54da3641c2a6467a7e0bc9fa337a7c385be75fd8772324908b0b1175a11b1d7fa54741bbcaa508a9d4399a934b83aef880192e7d42aed32989385980137150246dfaf2001259862a3b544bafc4a351879d1e3bef4842770615f3925dad7ba4c752ad087fd73ddc674e18f4bb367c6c48c2dc40521a62a024f68c02340047e68f94ed6565a112c5a3e4a73bc600605caeb49eef158819119ffea4448b89f8f789d8fe6388db1ed239be13ff959bc5e720f2e18420b37dc27ffe9ee1c81d8ced60309fc9000f2da67418918117295388f57f098de0b6dc8f3784bdf4deb9f43ddd5c9dd67b60a5bf901091f8ae6394e459521c62f47284bbf0cadb073dd7859f2793bfb2817622593b5d8ce1f9c5794de71555b1294248d06fc37b70962f10c5af79ef3ab0c7ca7af1c8f1f4616ddfc31fb74eb183d16fa52501886fc0b0396fa212c3b4d6f5da1e2c316ce2528549581c64373e4b26670038ba44fcd999ba5bede2c4fa65cb90589cce06dc9c3546d3deb87f7960567c443e66abfe42f3179a2eb0bae283e5db52a68b923d02d8e97c58ec1d3dfe9dcdb19b98e159f9c4de05825d8d96baaa8668f21423c8fa23e61dffc25015dc4fda705a31a8897e20477935e67545016eb58607f955d299d14f06602fdbb843151e7f82b5cd3d66fffcdb2baa6b89af60c40b32dfe76255b531615e425a6d18907feace4276ea318457b0f1aca08e846591d0d30cae04fb49d7885dffdd1750f9547681578fabc4907a7626b33137304f25210df8f9e5aa59f151623fbcb01b81fd24f655faa4004be8a09129bf593aa2a664bccd221dc2c72b84a2de0239dd4c71a424757b9da4dd17027b5231e18f6de30e0a98a309374385d60660487dcb3fcb19b02a05756b21e46b8dfb28aefc8a5a48fcfa55a2ce3f714fbc50c419954ab38aa09fea2d7938284abba8513734ae09643887df24dd3f293579938f22e2b91d3e383120ae1c1dfd295ff764386204ca186eea6178f3537c84ca6b072a02fee01465a4d1481f08771482f94cbf9cfd33ffefabb9fbdebc4ec26f80f53ff7e1e1696ec344dc421d41aadf0e25e6525ef9c1780926e9e806d0fe2f4307cdf737292f8fcca128fe10da85070736e6fb5e5c1b096c4e44e6b4088830c238c15d46ba901af9a37bca22cc46c866fa37e92fd3eadbd7a25be56fee09464c4bb458f69ecdbd1def292c716fad0c6a0aefdb851010ccec183039461e8431403ea1a988a69dba28a96653211f1ce0dfba0445a827644379d39ab5e8d5fba7d63b5621618b9a3ae7f06e00491db23785c6254e265f8e0d58ef9a935718a17e6ed64f334a819fdc873424a84bb9f57373191e429a5d2cd30234870570f0f76a3fe71d9e5117ebbac91a5f5e7df02c7379de5e77026cf7a290eb1d8dc4392e8351f1342ae570c1c0fe3a05a7df9092c0d64c951e4cac6bef6798b0e8fc96458a66e6f918e60ced440a1a2dd2219d813d65a5859fab0f51dd346a70c6fe1cbfc6643d3ae8e9d6b11db1696eb8e3dc57e35f0c52f3f68abd8bd6e6a60c036d982cf7e338f2bc487187f376bed0059ed639dd996a392472a5b95747e944622ff2d6a558c20d0f54e2e993c6e566398870c3bace24a453f656af77b19bdcaa087ee1196966698eb55ff5b3a484bb8748df8385252ff2459580f565f7969a82589fafac25033900f6b8e186c738cb9b75f69b972148c8835081e7b7200df08b91941e907010999afc3cd04206d8a92db859ad663ecd104b6e073f5d69a93aca21c2dbfac3ea8488852b163260e15b531bd6172e99adffdcea049e16ef8dfc1ed4d92784536a76b1bf6a805c6684abb87b2a9d9f75232e9cd2d24434917d932a4aca5885e656e2191d432c7060532c19263953ac4ae5cdffb3d18013d047e813df7423860ed82417d0a918da525b1e4c5cd61177c08295b5b8adb39d87dd2c507d1d3d7f08e63fd7cabe3223197f02faa17671c8add88af5b00f1cef6c2b057924f72ac53336c3e645803ee71a476ed31681d6381e56831f1a6668d2893371c0b662cbf4b23de1793ad98a7a8b072df97348644ca877087352cdf2c012bf5822f8a8d9f54de2765380f61d17849fb52a29065fc198c93fabe8cb3fc64383267ea4ac17a9d4fa9f274c0ba99a5bf3c2e7d3ba3197e21d6579e0e31b7a7af1c97fdc3ffe90ebaf4d903a327f85d6afc23887630540697cc566e78d68b30c4bb61f78b2db3eeb748053c82b7386b879fc49f4df31d0b7601ccebc7c788226f19bc97c70f93ababae99cce7be53ecdd3c5e6512c462472d8bb9fecd7355cb3045603e912fb728d985af728924e306933c81066aaedf4ca98adace5ace3f5573fb686b1b5f7d766105ce50696568562461ce2e010cc08088335b9e3d739d43f1876a7446061d9ec5226bd17921aafe1799bdf05b744b4617bdd3d8005b38487bf213ee9c19fcd593140745a229d209583838c1c818176c977749c8065514ed24b7b5b8fc1caf0da92412375aec25d309a5246025decd7167d8d479fce6ce42b91014ca21e165f3f5b372a46224e97837cc5491d07b157ea8b8759733f304f1a8ab63d615d11bfda58a06617e549074494ea32542ee32f75026eea03e2fb69e6e2a6d1ea19ac7c89bb088513c94956e57a0cba65c2d4e02df040f4c829a2028a8b8b6183c20a097973701146f538b8b089fbd2a6d356834dfa63ac01227c0e360236a3b8cce4a57bdf360f02cac5bd50e887d911b5a192ff565511a1f6301544277525d2d04dd4b21a700a77dd6c4626fb94b8b6d1efbac99583712044a1395292d239f72e8c0b9eba4eefe34ef51066574ab39e415f5dfa34d692113eb2bb4f7d4cded9c01b8dad9be75d7296ce95ceca56e050f156f3b57dc7213b2209954482f6fad04f170e1579f06a5ae4fabe4e6c993c8aa338034d536b264785332d964387642ff0b1d0315f3fe8dde7ae9a4bf0e3128abcb2f8c213117178f14d0e7549653a30c746421709dcbaca35dc98a4eb27a73044feb8409bf8a9dcdc05de31d6320a25fcd32b172f13e7cf63d3f1c70cf9b0d901059acc97c45f7ed291b0fc9d4761857ec09cb8a02807d5f2af60f454c2b007ac3b40e962267c4a26a5bd8ed1138c98e3c8f44203f307ea454c1afe89784c1655e89266965b2cf8e9e27899faaab7445d50628f1b0c0c1f8abac0b44acc9bc3243b5dad6120533a619a0ee578a864f33cb4b6faa4a3dc6431714908d5c3912745cb7a39544e3fcdfbb6224105267f6e7500fabfaf4493feb857cf515b9eb008bb32100fdc578ced3bc5b4214ddbc60c45180a1dd9bd7f7e28298f1fb8e06b32c9512c3c2c0d20777f4417acd3d6f503b945f5f85fece9b9f7207d448a3456087c25cd9c761b851390261bb5cdad099f64b7951e2a65b5d438e8b3ae80d168ba7756cc2546a4d364299523549edffd6ab743abb93218ba922671c5c227bc3a4c8a6f8f658a8d1303f4c19d729435d550b50b37ae09527d5de37cce682dc537a51217429ba3c2336d546556a07d5a3d94a947a9aef10a8d0ca2effdbf375f62629c4a1c8a31dc651d3573ccd3185bd85cde7cedf0530803e5b1cfbc828a5cd6f1b3526870dd360a78a257f6482f6f502a8a72decc1666200c9329913206b213d9a0fc5fb0124e349d9802612fcad3d474c0582809188c899150fad3ab5700bdd51e105ba839a89ffb0147491b11a2e84d70fea22ff1ef562b0184f7f2a22ef70c43a81b3b398d44268c2f555ec27fc4c13f56eeaaf8193e11e5a9979f175fa1de23196dc51c6ad6307705e38dccf1b75cca33991564e61c86386ab9bba90ee590207784e9fa7233a441587bfcead7be43b68d4bfd1021600da3dd3ec77cbc79f9f5ebe46eb15ba256c9663cb41d72b8c96d68f3190b56ffa5b29faeef086a259d138dab398c18d8d791460049485194f562516bdadf034abf10a6f81b52576cb090338468459571ff7dfa90656570f97e072e3920cfcf9b9d7f8eed6205265a91f8deaab6082eade48ae311e512de12d9aff4872045e8eb3e15b76b334dc4208f880a6374cf4906372e5d472d3963c392f90ff4272c143581456aa3e50236ddaae92585da6232b58dc5f1ea337dbef4dd50f2e57f1c6db79eb0c37d63a13ae7dd504199a2eb70b006e312b335b241f2e6562e712d47cfed286a86eca5390a26f58bc8041e3f77b77fe43d39b10a8f755156af679c1afe68e5fcf9110d6254f38ed7b07d015d653f067c68e7ed755ee21cad43897d60c1a5931629930eefc2abaf332ebdd5d68f46164b8d1b19eb60895a2914b8a0937f9a482a5cb068d8422d97f2e01ff350694e7b66dba34e5dfde7fc0240d1999bcc2c0b9f912c5062a169207ebe5baec4327b18fc6191f17cbb5b2ec3713ac942517688bf8a576c33f61f9a3e957f028cc4af4c8d521ec576190f2786bc8e90b5bbb8f073cf44255f3d7f6069f7dc2baf39582592b923d7cf2fa70c5771746eccb3f082b8dae999a67a2a0b4c9a445783902a1b5a0c1d9c4ca23b73671335168e5949bd01f9a8501d8c4422e91c3a241b68cf90b6cd77a906263db6ec6dba324cfdc480310e59a0f4be2b7fe0e481ca2e9e3f612a0e67a65fe4e9e3cdc984a767fd9872d575e1fdc917606dc8cf9977d13aad7b0dbdfc9055710ea98d06b5be459f99c88deeab4e205e997cced7764105c9490c115b125c5e39063ac4aa3237b1afc1349d5312767b8c36983bb37c3fe9939b1caac92ef72bc747be58d1fec621be0f0217c4fb399c260d05adbc20939d01446f543723b33cf9468cc90cd8d658e119fd1b49b85fd61c495e50d5f82085f25a58accabdcbf397b017e36dac6d406a6ab8be59572a70b32dbc9b0244cf78c8813707430adb85166329cad6dfd186138ce928245d57392231d61c6d5cf13c9c0be50d5fd89661872dc28ebb9a71a010ad66202720fc16e282eefe50ac4b30d9cd5a94c8e3b12ab14e251a02dd41a0cfad8fde36eb7a113e27de60c94140dc7858f5148b4745ffe7d67ccef2edc728560d771188ac4c854252085ac73a5c597f919c59d546e5e0e163eff54d0e6a7f70accfede039bf2695d04b1b040cf34c947839646f8e0ead8fd85e9fef6e33f8a63edf5535dd3fa91bb8df70bb11da129feca8ee0b13f7fa743611737dce32f5f48f00a984d451dcd51e1bb843d950710d99845531a3a86295d9d3d8eb73b5f7c4665aaf90506277c4972c8a68772129c72c30149af1d3eab07456d4ae7170544b5eacdd9490a4aba6c487c8c6c9a085fbf330c3d2dca0ca25abf3a27ff6738447cb7368c57d7156fe7a3daebb48b892a42498116815194cfaaa8608de3e0159344ff41bf0d5d166da0f9e22607b463a626dcdc2fa211b732d192e9886fd98d04bc5d25a74ddb86b652dec9709abcae4b4586ef46b81a39009b88fc0a6a49a00073750630002fe673e9202634117eefaebc393aebbd6c394b2172474d241fc52d84fc8ae089d27f731b9f634e74becd3d0c20d516483f48002d617fbe47134e94e0c1018717a263b2e0c0fc799ed5989d5f1d0dd6a31100ef272189b67c085da970a073a3c6b523a18d8cb4debdaa31d5260b2ed853b9f8cfcd66f3f629f5c576100d3d97a1b37154ccfa1df01834dd9a8ba0e08734774c9442b46dff5b14bf25834f738309506d3a4cc7d8da9ced2b9ccd9887507ea33164e7a17e038eb096713d009d71e64c8858f4a6c42b89730375aa8aa7672858ceadcccf9621f815d74df0ac54b80a0ab3bedc104648770622f070d98950579dc7ce039f28fb58286d600d8dbf6fbaa314e9115823af98d2e6c931afccb639a49a31b96da5ff0df16a92a8fb965b21e5dd78abf71dd1aa7c56fa8631b6c9c5a816a1c1702ce229f27e7c5434baa8080e537ce337a1f6d6f7b6b4d5ed3102b8b3041ff0623ecaaeb7dcaabedd5a5c45bb57ac84b50a8b95f5fde45daeea7c59cf510017c86d538953b06d95f12d6ebdf1e0df6b7ce43a4f649ee33126c2c1c8ad2c63f547a115428ea605ea866c5fe6437cbbea0babef016e250d519a068944221da92fc4797b2ec1495b8c6182d0183f30b3361f59f53b19ae85f1814855e17e40ac59a3f5674ce199fa42db7e12e786c7508ff21050097348ed84e0eee1148d9466671e5ba0db282b0dd9d1ba9e7d017862b45c68276fc3d0575f57903161da491491a6671f20ce76bea77fef874cdb58d1bc9e6db47bd3bd23634dea4be9da21415d75849ebfb9eac095505da7cdba2b9f0f0af3029f4e5aa76d7aae16926eba651471ad8d6e16cea0db5a7e75624ccec7d94e5e48627eff980c61315cb3c0c5a7bd841f8291bf9b115c8d67439c46d12dfb74c13f006ddbaf4717a57b893c76a9d02e9ffccf9fb2d03030fd6892ecd8593a4b6626886e8f47af31a57977a04a2018b830990bc5678d0c873e9709c30b98932e26fb40d83d53b34324cce037079295c16c0c1bcc881afae1893ff64d016239b879649202676c9ca3e43473d32d18106cc9ab0cb674bf05fe16370557c4a58f61aeda28f30d852bf10c50b94cd399e63bc23cf87f87f762e9fbdbcbe370fdd4887ede923874ecdb79159820445ee4661c40c92f9142f2b5a80ef06d6ef2b7acc4100e175c45de1c2599f42d8c8021c4f87182165ec5a02008cf2a1f2b4e6f20cca02c920458df803272aba9ce1fb436fd4eb8c46494b92d6c2d7c348bd50bee647b9bcaeedc8d3a728c22b71d3ffdc188815dcdee70712694b90013b9759a76154035dc983f6e1adca1ed56cfae28b59d72828d94ab900e9a24f0dc90c7a7a5bf6549d227025e502898d75770a1b1abe83697c797478a649a27357968df61c8489d332d0a8a92d1f9567697ad1dc86dda56c8fd768bf7a313b323ae10f63dbd15d42c0559d13c0078a5e0b84e8da0a8c65ae737a5db1c8130fc7fffda1b47650b6fbd7fc197ad0b3e98620e5edd0d82f5bc811eb3088179c96b552e84c0439b03baa777810b335363d23d4414c183d90b464a193d4355c400c1953f6f5b72dc4cfbe869bd935b0e0f5aaa47bcaaa67b32c2c19e6f8cc3da6f5aabfc3bd05acd20e6e0debaf77e128a1584266c8ee53eeb7506c3fdc9a28df9a441a21b400c050c330c8277be3ae7d66e801cbea5e65b04d715b5c29ccdc9fc7c536860a211be0c03e31ecd55b948dd5f237b66feec64428c3e3125fa94b209b85b95bfd02c866cd52067cbb6c263a91bf34d7d3e563ac9685a0b54c8630bc8db565dfc0f9b4b57ea15895a35ecf3f13ccca4e5e8d62e12db1c9d9b4f5a29c6365004adf9524bd97070c3e3ec6b782106e1a6e7db67eb1f71244054a760bcb4a60f1071a4bf27a84388218e0184651610b52309816bc96c360200e54a5624a4a7811d20ebd2286f0482fec7701fc8e61d301b4d182872f0a95d11e0704918ee7270fe3416ddb65bfb366817626e02c038b1b919835a80564feabefa79ac4b99097c253ff47f5930e66821fcde5d78b5f23a659cab954a22c5d6b73356ff8810d8d4b6b84c53ac5f0c007df7fde20556b2daf128ec01fe9ef2fe5b2daeb59bbcc8854e8c50222af24fab2b8dfccc828503c9a5e400ef69ae4959f13c23b3283ad1555718620d37e455a32b7af6fe1b6413b8490c5b343cea68aa4a5a96e46b853638e244c7bc768e0cd781d1e1d6817f403f94efc43b2cd77a3c929e47a80c784bc273e2f3f5780f627cf1c7758689336972dda22bd6b47a62de3dbfebca861c0793dca501580b6fde1e4681a47e980dff5f289517846377c9063818e40d1eaa0323019d95d126caf3cec8aa3fbad3921aac4bdcf4d1a84ff4235189c8d9039ccd771327e13c17bb4977f45558ecafac2c75fe95ba870d496ad761f671918e4ec724785345b295ffd2362aa01d8591d8a8499a33ac60bb0dd1cb3460720ce2984c4fd6aab3369289dc32bf40031e0382589e49bf932004704e4cf889ab921b42d1e736c4e5788bfdabf1dd60062fc2e67fef466d4b5d06c534b31035689f87a0351c51d046b924d25b0e10221d3043898d8e568170fbb6f18a8aefcf90cc96ea9112f757df67bcea5e0a0d12f8ae489eda08c57ffe748c9d08210690af518016119c74c3f9ef61110b2ad09727266e99d1c55a47cb1e532bc3951e3f9df5f00ae0588956c1f48af1fffb89f8e5a0c88e3d655174f3a8b07434380ed679c5e40410457b17064021a2e50f3a428f90f9b1bb7d4c9432705cafd5c9ee81dbea9ebc6881c371c8482f3029f97195ebe6b35a913290f3afe55fcf201128c77f414515a9059cc090adbdeeea64def01753ea3fc0867f1cb9096d9436624be9571afdfd9ad8afc4984449489e45615f67daa660822e4c891e68a31d81521b1089184a0868fc0e88612b4bda7f459184090baf2279d3107dffb273d17f72d3e16d97b06b1679a8198f0ed536bfa56ed8c914bb1a2770b86f5ad5972b72944fc1073fd865ce218a3c1d62198a6efbcade05835c76bc675576bf1b164527af6ff4e11251eba5d377fae455d3fee491ecfeea96b90542fbdb29ad71f18dce0281e1dee76d06fe204949fb89db8d48d2aa9b18efe663f46f219d7d4ee8be7a52f6e264b75d0d1dc15253db25fc594a1ce1191a1cedb82fb234c9a86476f2dbca5d0e40965dbfc6057fd751ef47514613d95cd463e70948ab532d0de62c459b042cdfd69514c390256b83f683a0f104e9d0890e11ff213a883af22d323465d7dc8bb10228d2a2b2d853822fef9b621209c0af935d2379ca862c964281e1ccbd46a5dcfad209572237a2b11b4747f042ea34abbfa648ad9f43d216791a1f57c28dc5e93a6ee7dd30682eed3c8d9fd4a4a39fa405cc031e9128df6bd4e03ac8e268f050ed64cad24eb1981c91a62b616b95b70f0c7425873e4c5f93713deaf75596cf527293230e6def81d06362855d47e485638dd13c6296bd6f784ed61a01d2a7e9b9a424eac4900d9c28bc57b44104b4694422298ebe0d2d0775a8d34e51c13712ebb91855c273c44aa5faefdd6dfc1043187f4ef346d2c370ab29e3cd037345828dead7c20d6676b15f9f93e74a2660a6802833dae02e9dd11cdb281f03e6b0201cdd0f33df9904ca4af85912dd930ede7ffed8ab70cf6d234f0e77950ecd46105ff688550571e37d5207c80aa3a1584649a4da8777f66b064d1548994b66933232eab2eabe99724a941a17d35bb73f71852bac4ac682b09caa8acbc2555f8deabeef35660b47ade56979ac06f265a3a05b758dce5b5044adc51daa0cb9636dcb5785286d90c34fb5700bcfa1988b48696ecc4e38f617deee00b2c5a0baccaddbac1f02dccf05836b7c26b4e0a357877f89acb8ab910800eb254340891206d4f87cf5e6e1646293ba2717f994ae65bbcfa60a70ef891afefbc9ccc0c7eb453cf24bf29878cb25218501ff710919cf87f1efdd13acbbe2de883630d6ac6dbd9b3e9dfe3d4cfcbea6054c156e58a3e36e263a221135df8d6cb374ea35707291daafefbf681d7046d1fb11fb592366e411a4c7c8c129a3476430eb4e8c96857e3f4601f29e64c727dc09b618b9e2bfe3fbd585e8279344ed66b3249bdbb074f895fa3d802b5db89d124f52295b8f6c89cde76f91fc5bed98957c3eff0269b4e27b3cd48306fc60926756de37ba81f31dd297dd681484dd4776b0b06a6de59588ab6f4279272ba8be7ca2493fc2da99608625c90f1b8e6678457eefff43e2131e0019814bccdfb9a3b51049167eb330ac47754c2484db70572fab7d486346f41eea7e737962a4ff0be6a451305ffdf3828fa9156ff8aceefe63ce3e89ff2056b178fc1d92f94ae3a621abde3c57db3f8e9ff88dedc44af94e7a016dd6b0118ad82981660d3a496ceee82c592b0ac050d20cf3477e7f6afd31bf5eafe4b941f58ef5a967c7c9e910912f8ddb3f07015684c2021766ab49e42a3182b47ae9f89cde9aeb1628b8093e31c682e625b7f9dfd78e3f91a448f4c511ee859fee342334d3dc73cc28e6666455cbeae258c4b5ea721bb19dda849d2c015cfdae7ae464201ea7015d3d67f2ab4cefeb4dcfd8e1c1d8696c50d3afd2346b1953402d466c85e66cadaa1ddd5a811e754923cac9ce5cf792ea334003a0217dd86d69cbc9aa2f57b7a6ad5d5e514771082f98532c48f27b9e4b0f097bdb313c8df3c73be8da84f19d6eb62bb8fa9c1f629d6d947279a4914bfa47d1cdfed483a4ed3b6597b266d74d8778c66d6e6f3653fbb774b6a49e82e022e1e9f26a8fb82dd89031b4d98a5de5e54e4386ec36bb6f12da77dd1bada0c0a6afa7947a69efd6cd135c704f89d894c202c28695c395e66636055a833aaa997bff72fae213e058f5645e12de752ab09349cf91006c42ff15c6f68a4cc173b5c1a6e744464bb9e3697c711f2a6ac3878f3a4446024b5e7f52828978173118599654e5c5d14f88b393e549ddf6615ac4f3fcba58f3883a4234cad421fb5d5aa522ea074e03868d6581799905682d35347828bd0eee1028b4ab144ce2bb8ae58e8830e7138a111fad3aed0c752c5a64e12b653fdc84e83729fc25151201b5161abbde872e212a700df9e96add80826f438a964a830254ced0a8fb30bdb3f64d436bb977991c7a9128457196ca08850cc33a96707a6601272dadcb8b574f5cf1a53c6be0d5d871c6a73acb664de6282f02aea8ea4babac63087c7a26b165e49a9edf37be57020af732d880c4db91d21e994bf0d168064606a0d62bdb9e4ed6a2b63fe3f3608923a13ce07be6831df5e1d2f4b6c2bdda475ac7f30a68487452e3a901d3ea7ff9ca4fa5bdac7fba1c574cbb1c70e82950b6a243aa6289297b904846693fb6074f8ff44a9b20d0e0793598b0e0f27286cff383b5afcd2040bd23a318894c3b74cdbcd1a17e096b637c8fe9bc617fac2bdafd31c2ae1e8e7a1c69baa9bf2afd4f19306443d0ccfc00581a3686caa1e30da158d187d7cb83e8988197d71fcaaa89388828fbbf90b7faba1a479a21fd413086e283c96196b34055ba6210ae7a8e011d33fe03ca056ff85950cfcca2a8ce74abff593a78d0b365288437c4a8f584fb183239de0f4f334af0154ef6bf21c4e39e85ab5a3f6fd0fc8b0b819426ec43ee1153ebd77ce9a51f1b93b7f31976d892e843160d59dcc1e81d6fcaf332d4eb516513410ef5ad45a1348c11f9bc320fb816cfb3bedcc84255ae5a04acfd2d801fb5c7a7ff5c2ac6ade4aaf92520892bc47a96ba45726ac84e797d5ca27f44b8310ffff5e5e9ca9b3fcfdb3c82acd5b0605e72cbadc1aa378e83d4c0f8be5d2d4be5c95e80d66625c61731338c016865976f02c4064c42919ab2abb3f02f78d0de956cd80009c883e0fb6f79c234795a9a1b2b2a5f86dcaa72231557a83d496fe6b6da90f61943687f0aeb2f0d6453859941d4786bb8de2df05c8f3d1a2dccf4381dda918fd07c245d4a479a48d8b412ecad8458201427c0c0923f9527818e6f1c3589a57cb20408dbee4b536d59ca6c4eeaba30139d162d46739d1dc5637af65cb6ae0561c6317cdcf570eb4b1b8cc2633467addda7bedad1ae5fd78561c7cde9c1de5dc3204885bc8e4c04fea049edcdc2b348452f42212012fc08a8528b3a236aafeac5821d6966b4b18e69f642a04ed54b8c2d7811818bf6cef900022533509330a22e4c7e94dd8d43e22332299943089fe160016e705828432c2199ae1489b19e9bad8af86d5d7fce476fee9c1623c06315e6c78768f123e33089d0d84f5cc6c731dfe979fdab1188704e0c9a42e4f63991b04d7f62bc37f209fa3a6d1f62afdcafd1d46900468bdf25697d92fb6cdaa0321aa58a5c957ce484eecd41e40672d81339d5124c0bf1e0cc5da3ae690202592a749130ad6ab255f38f04839b9909f9e1f2dd0f6d55fc2355157bf8a89deb63c1d34e3a75a80665b2f922be154918abcad2534a9bf72a05d9d7f98124b0b74eab43ee3db573dafea2058363064850db4d6929b01c4389358a79354d376d75cc4f21921ef893d53c7ca49c69386b8dff62807289e8b3e0facaf88a448e47d9341c40e35d6d8961da6cc5f873ce2ca88d46ca9fd7668955ff9c489135c3294dce3e0eebab4a0d5ee70c7d43706f96736c1e8b0f65537c5dd476200211b12a34df7394d6e13f4eadb753fdcc169975666bdefbd2600f869f10368145bb108dce27158fbfff34cdc2d52408f0e5b2ef7a978cea76ff4b353fb68baf4b2e7be24acff3885f02a0300f9718bc4c91525332ba529b6f7662c79c2289ae59720bb12e024a469d6638b33936ce8300e80d2bf8bdbedba7e8f0a962425e59d90ecdbce2a22a9b69fc4da3e2f9bd98d79a9d738ae861edd6df7ecea8158ecd2309fd6b8ba310e4768b287e8f000f5adc320095a35ff2d8974f6de019c0dfd924a4c1315b3c17ef4078396fb16f3d6e98b9668304f092df7a67edc9e18b0b8f7790074daecc157297e0371be15cbbf32770e9a1a03f6371924edcb8c8440204b4c36164fac0bc7c59ac89f54f241e965e65481cf1874443748a19f7e99f2bf2742840940a2fcbca155019db4a41217e56ac79d45b8dca764f5c1c2679e95adf45ab90dc99a9724669676b7a755e1b6ad945a98117fbfffb362f320ced0961e5a2e325d178eab34f5dd40a74b3e32163c94ecb8800cb3f5e4dc4009612faf4af04f11d170cc4d7e9bbb51539b7f9c7fbb53c89fcc7a691c99dad5b2617d6403bbde980943da21af1a88f0d5fa96859f57ae89ec5c62cce60029742b91f8d36b3512f10e30aad40ef46da017d54351815515f1699e905d466caacad4b5c80cb82fbe62a1ed617477f8b96b28fd626166f216b00cfbf8458fd2070cd7a04f227d369e0d1eae56990ccc2b28ac625db85983e4f73477062a4fcce02e6dffaf59c17e97768455f3b1641267aa146f6c8d89621c2f2d9ae556601ea3ba8e08f0be1473679eaa356966b291cea75ab44753c4757b94f6fde24de5d2effe727228c57edc610ea3a14e60bb33adb3e647c683ca2709adb976d242a3ee4590b534bfef46fb2991bc5374eba2521c7d39c6d468ebb7f518f4a508bd47f9c745d515db2581c9430c92c95d7a1b1abaff52fa8ed5f6fe0fb4bc14f9fd75d36b46d4634f509fcfbe50981441f2e3f8507325b28d87884224b63ea3d667b85d08bae39d6c124292657ce8e3cba242d9d80e1c5e51be4a5fe4a50962fcc29d3ff00cdcb4c2e5c2ec8bd989b1362373a0ee6da54c0cebce75a8ec8a7e92ca4bf01df5db8dd8dd7aeb8dc8be3a511a08f57b2e1a94d859ddcce5b6b089523dea4cb885200db633c89495f7a7333d0afa1392ff5cf9611441c028dbe4e8afaf6072861bb2cf0ec1d6d1dcf4a44d61089b1de237026a6691edd0f4491b460dd7b69e01a3772537747db0ddd14e65e5bc07aa9c3fd2370e3cae1dc0015bd3494ab60c289f5b7cc2428c631f92a902c14b942a62c6c137986f4c590b8c8b449fda1de57b1a8964d16088a75e6ca754e4e57f9e93db75a34690b4260818912b021b8e37740bac47149f9e253f965f8642a7a1360efcdfc6314d5f484afaed8f7848cbc278b701fe0000811e7262b9f8983123be5df9c48452c66178ba72cbbb82a53d3e17beb645928879dfff4413627b2606234f39c33c5c688002e86abae743be2d443ff2c885d48f48417080da022fba685d52e692515a3bcf1d0d05f76ccfe337cef76d37f942ae10c8582ab14a97e819a8df414763bcf6b786c0748a29adfbc1c3034f5baca19ecf89185b1e8c0d1fdd6bd8d33a333782779f1a454b06f783139a2e7665b94db7c772bcbcbce7313e4b1f1dddc4ee7c4ffa0d1c729f5b7c850e215eba2a11aaf2f69a16264aec3472731d7f1f2c6bb86c1e623308ee785d16444e382f4470c2f525aa2036c2c552519f47aa7e59304890fca4e7e5e4bedcd6bc3296d92c5ab6e5b64f184190d9126dd1bd3882b96261f77ca1573030283ed786e04c9a04bdc407af4fbd9d375b371ae794519c7a0426d097b099d1e691d866ead7ba2cd56ffacb0e44f264c63d1bba8761efcea600d477b5903673f1548c427c17116b1092690a03e23ff540e1f11d789b093d6831d658c1cc62593b0dd0e7256d5701a87467f366039ee1af6bc60ef1f9c99c7c819b363e4119cc2b0b20718f56ca8a6bd33afb733fc6f09a5ceb6d493c2866aa990673e84a2629f33dfa68c37afb3824322c93c42a944329dbe701014721a4b5254e53c13e2ff7fe7aef41a719ecbcd0a0b82f20ad6d29245d5aabd710d6040b8c9bc285b54ac8618f3e7147c7b94c989f29fe7e55fe87d846581f27b32a12e418f298186ae4244d893e5a42c81f98ed95775f0fa1411991ae61d12ce486f117200a53ac21feb3136d6722a2d274b5dd9a83628deee049f8db7195087be451389ec586c2443d4b0174c5d0c8accd1dd98597fc391bddd1c5159e73fdd7be210dbfa9fa7d9a23a8f77ddd53f44254606d7a9a788796472ade59cd6643d4f7f80b0a10ee246ced5fa053ea46107bf861cfdaf662adcf26f1c0120d06e5756f68fc9f4ff790cc2be914d7edc2287c27c0e26ee2e8911c778fffe1268d4fcc8cd30f641a7e1243fb3436c8b1f9bfd1ff90d9dbd75d54f07407bf1b81b72899812e1c20655b0b6a788da269c8b4bdeb81beb459b094e8aa23ddba0a79d4a4cbf489ac44c5463e382a02bcb4d372a2fb30f3489d988e5eb1c0a690652c8da2163a43dab45d992b6ae9f9e3d38d98942ee50e36f5037bcd685c04d502159531c8b46b974f4863941c4a3edcc710f514b856db08afdfafdefe95f8a7508c8cd568cbd8643445f7bf47cdedab7873056f95fe06d8b62c4bfe337384d86d03bc5c07a91ef5f48df1916c701d3501a2c854a9e54c2ed02fdedd9e78970c08b7fa4c789ecf363233bce3ab4699ee2629617094af1109ed28da993bb5518181798b1e3f5746b1e58cc63c78e69888e43de8fce2e8defc12aed313e86119cf94bd41b22d077462167713e21ddbde3b146e41737910b471ebba0d81549ddbcbd2f3772a1c9649fe3b73cca80535af34116f494c0cf63f503f0207307992c552fb0d8aa0e9381774954854ba3250b5e7b39efeddbb1233b9831a0eeba2ba9ef0848795ea62d1aeb8c5fdb5a46cbb3376551e29d59784187738830ed0089608c35cde4f84d9ca06ccfce05e58d8e3e51118380e504ad0329322083167249d6224c61a59208f2361b694e9f1d33427bbe9e6bbceb0645f13c306b9a647d4f73db245cd0c81a2a0697ffc44de5f4795fcb50ac1fc727f17c432ce1effc8f45dc57d119396b1c4a3a2e2047fada5a6ff406d9ff5be092f1ddd91786f708dc7aedac2d017977420036e5189bddff9d03a9090337bae2aab9d1cc94ab213a50d6edeab31d2dc176a688ee30d34a502c7f59df6de1875f1e6a088c0e56f96ab74c4db134b145e8fe103d804391366f42c86d9a1eb3ac381809da453554361a13f26eadd804bb827a2ef249f89abaeec7d9212f544f2000f73196298e60a73b47d18316daa0961ee7bc4b97960eca0c69b60e1a930cd148f709175262dd5f37098bb3ccab764a09e0b15e985e9f793065a76970bfe97930ad2f8cb629647beb74eba18c096ff7dcc6dc115a1f695251502ce22cdfa2669914d694dd903e399a06e41c12ae2e789407d624256e37567c5d03c0eba7d813d051374e5e58833bae287eb1134d3cc119239f38e175c1874e4e40fad4d0bbad97e7d98ff76e67feda04c429041729133862cd1ab2bf0eb7269096e344407476c261d5cc8d8065fada0d3593a5bb1ef15f084347b046f00196b30ea18394afa6b561a2484070f62c475e5693e5a2c69ade13ac2e46b9051d979d3c83dfe04ab24fed57ce38d2434feeee76c8d251c127d4dfc92fd9b5d4751eee4256748bfba02032ea988c204ce04c3de053dda2f8f64c5ebb9ce5adebd2d79cc2eb9cd2c09113da72e86e148436cea60cc19b9f5d52369340be86001cfae3b61cfcc9c9037b3608501f7a7c7656728c63bcc0c81c88e0ff151d4dffc66061e6c83cca1905fb9795dce01854cf619f90bca767c00a490e7908d81c6497e705d721c9f79a4dc4bfd5b064a99c8124bccda9b47154aab788dbd32e1791d87cec204859c727515a005f2969d0117741a02dc8e75b1303e6344c5f8533a7eb5b25049f8ce972a9ae053da390a181534db28f6d8a0870017bebab13b9b8ac086ee87bb223dda0494d41385992118fe7ce9c327b33dce242a85de991ea96f869345f330b5a749e34ca07170e6144714270b5fa9d87f78471cc617cf2971d0f86f6706721160d503a41b648fc92a7c804efe96f09b86260a5eeb2130d8bf09ddf60377f650c02b0790e994bbecf64ec386791aafbf7ce015fb265b4a945cd0742423efdc81a6df7973ff7ca3fcb5ae7fe8fdeb7e37a09d38b174a65fb53f240d692024a828fb284f4a6299f563d8e9346604fbabeab3d4b1914c63aa8a92f1d0557a7ea74da23abf619ec665d55a928206a176dcaf905b79c67310884bbcc4da14c2edaaafa6ec362b47f8803c28a02f20847e004692e9c93bc05940fa863717f8e430fc40b17d554b6a5b3bd61cacfcfbb220cb3c161bbc7a0d5daf7931780f0c1f1d20e3086360d47691ff7e3c4ae1ee8cdfb698d877831cc0258cbd6fea52b6a86676a33f466cba8fb88ab9c9052eb6ea418709138850feb0805508fbf173e77feee13968ebab5dcb6612c9f56c26baee634901862e51095eddf4d08f506ac3562df7482002fe78cfdd5d489f922fb3b5ca07c57091194244479a48774fe11d95a8cb04d8dfb1fd66dbb5ad7da5e31276d1fbbc1c2bbf616ab1008c6c964dd74aa15ff247c377fee86638acb009723d3e22bcc991a4cd054dafda9739c71224b7797342653b24ea5b71c904d399fd78420bd59de8404d081b6a177d564cb3f5cd05eb3b2284734828df0bf950e936a20651a2a4705adeb7c4072fb8bef2ebc4e682e8cb829cfa7b35604bb58f5cfa6181a141f61c990924cce3595ff1280626efd0fb0c345544361a287d21e99b3e3ff852f163bb031e40af2031fc44139d0139f0d4f4070129ea2c25001836468c975128e0cf7c76f71076de52ea62ecb1ccbc69e6d6ae42b1fe985045acf8af01a3b9f7325d7daf72b0a4a1270e602a6a2791ec7c3002270c1f6ff55539a93393593678d24b43565088812f2931e1925c38dcd07522b72422d0b5a84d8dd81cad0c12571ad6eb806f53c5e910cc28a63cf03d1f78f3bfbe20e252cc30096aa846edfa300e83bd8c5f36a1bd2a6754cfd3cef9b5845b245e305fc3636588c0a741f8b633b5c7a9a95d25d1147cd3425e1d4186a4fe419766e513a2a5ee06efe509e5cf5a678f0c3ec2c6331dc37dd140f2c32a6dc226bd4d3fba5296de883fe40f0bbe0356b152ed36255cb0bde8f4bcc1ed2ebb9b6a625dcd705d738b0c848c283d3e4b8c60c83aa2825e5f23376dc677ea11f649f9344b9bee571c2357bd9a5d30c3d801871821f75d220ddb41648bad01ca19cfe5c1907b68923bcd7c7e05417edfe0c469020ebd2ec5b79e4008b5699335331fe413969fca59fb8051fa396293e58550b02fc31f14e204908e216ab64573cc15e86a3b8ee36a100965d0cfef03de73f98180ba8da7db69ac2d52779c13a7339a92e8cec9d9efe506093843f839278204820e582265e6140c5fa7f5e4b379d0893f85e6853f1248b8f921e6293db9983cad868a8d501097aa6120bd61e7ac330ab5a84b6173d016c92257f112365b17a8c48229eededbac5b9a3a24161b03b2fab99ec085c51aa0218c854551f8351205d27015071c8837efc414f50ef4037dc9575748b8c31c705563c7dde6c2f728f76c62f31d764e6415064b2f8dce0bd154a8970a745083056eee46392a2274c3e427bbc6b0378ae4d2348c09b9ab6f77d384c97d127b81b66b532018f56392561f900ebf356e3ba80f947630f0b9b57f59bb4b53f87a0fb49cec408f6d33306981bb3b2c816358dbd2a7b837954b4d44e60d3eb7904e3e791b6eea7f8d639ffdbdc38e906a0b6741653286ff8dcdf85e37471eab9210fef353baf6a69219169f8708ecb1ed8b0968ba06fa1dfdaade9516dd665985909188611d89c6db17fbd1bb840a0c55aa73155f98a7ecd52f345be18ee694e23837c42cf02e0babb0087e7839e89c3643217b24b61356fdc0b9bfd49c5032dbbca9276d38fdc4f92e30e4716572d077347f5f5a97058a6e62dae224aa2b04a75bda587df743df0a359d2a0533370b0bf42bfc0788afaa02117770392d2970c5c2e0514ef4050f668dc5561f29bcfc9e85ccff2bd4ee8afa6753bba61792714235e4618cd6a5b0fdaa37600cdfbc4939ea47c0ecfae584eb83b9abbbeb28f13a603211876a5911d37af2a34c5c649e9be85fcb3169851e09c8e81a4f50ff238962189ddf14c9fe22862f1e9bcb097b4eba700716cd5386597c80f2ee76b2519aa8a03349d2cd68aefc74334b74913f31924dd981fc1d968be7a2b9c95ed9e1f8b0ae8f67606f11554d6fde740315c349a1c666edabe7c3c7365b5f965fd639a2114360af6e898c9dde106cb2e3e1c35dfe9a2acf2bb70ee6158ebcaab11eef8579909c0f1233bde7b8aa7172a4a50a70a3494067729205280bf8a2d46e93c65379e8903474d8424f0a3ce87f041c4fd2713d69572c51d39f10e7cb7b5d17655f954f8378aa3814dbbf99683c4fe30d3820319d0202e08f62dd01937070fcd6fb12ceddad7368bcf10d74480e538c250b02aac88f1e38d12480546da4257a9c8aad9785f4057330781066633b2e07595037ad4951a9e932ecb1d69fd34f9d9a4e2b7ebf34e31c719a3ff930d95f4fc2bce602854c55f8ec70d67fe56688a680bf17face68eabc328ccf78098b45c275b367475898024308dd371955f4d5c0593aed2256eaab4e508fd4274e4c13819c63ba7de28daf6f831536f00733f506b1fa754a3bf44bcbb864e02ee981cc9d2bc1ec0f1048f0a10790f192e77fec3c34d537cd18ea0086e7f86e2d39d21ae5626928b5c826964bc3f87637303b8c471c325f1fa94fa86e1fbd87bae180535109ef2c843e9d4442d9c386a76c610800974399df58ec8fda7096ba9b7eca7122102293bd98bf36b11cf49a15f945adf55d81b5a2586d999d25cabd4ab77e63fa2f031ecdcfc534253d84eadc6587db9122eb2d83ed6230f982e20c6e476757a869a9cf41260e18d677c56e3b2323c745c46e51cc9cdccd7d2b65991c51e217060b42c0596ce665dd627e93f762d033f2de6b052810767ab1425a18d0ff556dff8546b6f7c17e5de6f67e88ad1ffdedfd397dcfc6cc0624f375d977b32ee98103bf8f42fcec755ef0d3ad06850d44cb002d8c9f436d2f499bd9b67ed3d34796265a394c7d38d4a75819ca690a2e8de33eeda8d4dcc6e4b6e0a0cb99fd019e306a002a2b3c3fca04f957eba8a6b2ee42df31da9f783499d8794bfe7d5f2a1cbaaeaeb856a98f025767c44dc1c1f0e5133139446b52a411d94dd3c9d5ef865ae77aa57939fa01e401cf02c0ef195d50992960499be5253fd29f6f6d98f09e4f344743d2b87970f7ab536737acca3f26f8f160f5604238dbbe3e05b98fddd2f9b452e3b30d116c8453b7020033765b87bfa4d38503884720cbc65a44d139b4206bece9821224002715c2b7ef54adfca5c2903c5c3684ffda66c7866a27847591466fa27a220a114b0cb5c86f432551237c2481b4978376459908ba60c58e6163c54aea95bf919548e36d3c2b6e915262a4a45fd43f2b06f91daa5416a23443433216d6e7d9dac53f71402aa111a8387e07cc2b4fbd7cfc6da8e517e6d8916520b12602bffcaa77b4651a7954ca1e162fe385d00e4a395f35b91d7d63c0d96082cc7a93a0778edb32c0ff8df65435a59bbd694470f89635209599f4866bc9333f2e066eae4b198ad0e6737f2ad04084fe1e146fec6ecb64e3c5dd96a508d43365d25c646a4523029009a561b58dee0cdb337789cb99d7f6aef5272b02aef4865cbbbdbf3eeb1b2a8d8f10ce30a9d301262a2501b1b308d7126f5b783e79eb948874b438fd412e2806cfd6b7ee15bd3fd7646a592d46176c02deedad87a08c2e6b93c3fd73cf0e2a54abe56dc84efe6bb694c7aee7013cefb59670408fb4ca099d1616bc31e14614af9b7d2e8d91c80a428e0acbe9a3fc68c678195bd6308d7fe7bfd1acd566a6853f7bdf42a3f4a490caebd3cbb504d6e440a8597199e6da467cc04cf9460876fc7f93a1d51991dbc4a8f77d7233c0d7b0eb4d43c7b00b9e34f0eda05f425e49fd98a6a81f81a96da482b9715b514e60db4e05ea019d0ed57ab89eed17bb160cfdb265ce8d4cb521bc488a631964dbf065eeb739aed993e6723dd0cb878dfdea22239e3236bdb19e78c049bc8bfe70cb2af7ef20276f6352c8dd7260943353e22595b3e3fa9f30212228830685972f2c8cec2cea791f3b60e0159e34e5d8d727a02d9d28dfea4bbc23c774f20ae22679e29c8f1ef669b07f6ed828b08ef0c2300b12f48b2898bb15b64cd3fdf54f65b7810ddfaa4f198803fcc98eb03c3db44cfa61ae7f0eaf61e0060776f0d405e20fe6f62a2fc12b884f96389eec07833dafe47e47f22aadf2a7a4e22be503c37328dd02fee8b488cd3a8809c99685e562a992609593d69b20e8662130f9c5eb9f3edd18c18cac2a693bd6ea4f53c9ead2a5aadd28ddaeec07caa9287589377f7060b94ac0a2197566349123587d576d71f0b828760ab5e3e077a1977d2ae3d33b92439de3a421bf70bb68770483824abf0f991bfe9eacb31bf0eeec21c31b2ce2fca4c70dbb864f040398f0adc1cfec28400384208dbdd560b97a64783fe44291eff78c765376000fe6069b2cf33d5449e06b7591b8477682b9055480be340325b142e50e78abc5a26a8c01edd48eb27e652a32413c682a70f0f05f28a14ca621e7dd7c0771550f9a310b99423190946b96af2b53fbb4bdb5418439135429ed515b80916f14e9d386409e5d386453fe028432ef2d535f90590c9efb64fe1c939ed083a0339e96e5f5e04023088e44980d647257ec16c9e235c2bddc9912b0aed8ba84339cee03084364c5d7307cc2ef12c1411104b820327953ddde66aaf9e5e27315c6170680266612c244962360bf9ba73238bddb859460742a7fe21eaae8356950c96782c7486fb19519cdd4226a0aced8eead8493091fb12417ab64dbb36fb28fdd5c990ad8979eb1ba319c6c10c71b5dc98424cbefa4c2cf173c8d5d60dad121a67b3b9903fd6fe04860406b968d9685d2cb589a92714f622f4d1155fb1754a652c91cc03f5a7e5991a794470a4eff6d1b4a2a0fe9ddab566f1f489700aea93504ee62b6967d4a6f48bd39dafe1cf14446785ea7c26733e83bf029cccbb47609b3c349d1a8f6565bc16ed2bf6ad093d526d3994e56ba39bb5c3d4c16cdd762e9efe1a315795857f79bbc9e1756ee4036788f8565a1d8182bbc2d5c6ea52c35e458fa29512e895619b5cbeadeb39c4c4e03668edc7831abf303a2446f78363a4dfbf492cc9ec3ebf03fc303cdfdfbedfe2ac03d3ebbc47016ce9676d2116608514dfb41b6b4cc06ec1b2446a845468a64fe72b08b9554a4f935d68c0cce1da32ea68b7f5cd4600653aa7f592e20d657e4a95d8c62d40f171f239f54b2fb5d405d01fccc484affc6a24752fd8e0e6f2d8411d8bd1d6f4f5bddd2ee4e6910011382d702105b1e7b1745bd2d7214aec504be7972066434c8a9fea1fb125cc5ae7e5e0550b6d56d6bc26907448b3dbbde889eb3fdc3a284e61b48d6fb5650336050ccaec65948173356d4c77ecf5ef956cfa6b2d30d8e95983ab8eb00608de2652860caa9d38987791ac012b7cdcb717dc5c363d715aa5fbeb6217c0cae596c5621296c35d06d35be031d1bd4b1057dfcc0b7c30cecc1b643e9f4c09371d3bafcdf0951843a2e70f2c91adff697ec8a036b45b32781dd804aae04b46693d3c08cbead2e03f269573f2c073e34c884829330ba2fe75e5fd331c9cd09185f5d4cfd77356534ba343eff09f2748564eeef6bb389b2af7bc5e64f29f903feb8806adaffc769e007934ce38f3c730cb9dbddb2b56c858947415f064aa1b473ed5fa4d3bd51017878a43931a101c88dd0fe7127b440d85721a5e700238657414c770d8b4ca9dea18d312cad5a0921949dc7fb10504a4aa966c6484ee4feab03d6139c5c967037ae48a6f2216a846bc2ca1a3dffe2cc231494943877b78b2d5a619d53eb512d37d5c75796b4fa297ec37e24e711ff550e56fa01247d141594a52e76b83eb56d0d1f71bb92ce9e9bac8dd3182a643ae009006d4d281223f778bca5e587c4c42928a91619f44ead3d3e4050d733301d3e9dc4a3b17c26d6d89d30ec0c51e551dca6e34ec063a122f466b814778aa29031f82ba2ae1adbfb39dbbfd311ab4de4ed791eddbada323e2f0964257a41f22e11d0a6b7afdd00bbbd9749d181a1f8af70d00ff63cf9e64547caefa400ba76d7189b817cd5fdfd277c85d37329c0961312c5153f49424a2e45501f3ea3fa082ab221033b75bb3714822c4f5ed188aa92bd20add8dd8f54e0e793c74de5f818fbcea864e4c571c6fa5802f2484cf583ecae5307d8e7d01e447ef1a92b05bc115ebc0cad85f4d571204a3ffaf73fda2d9cd4b61bdd00c5f86de7860c1ed500bddb862a78392d95718c94fc844c281998df046b74821593a55acfff4c546e9ace40f53ba26aac8a126aca92ba88ba1312a70c8b8d020f3076d423d861441a19a03cf3b38c6bc09cd7ecfce32f9dbcca657c9b540862b6f71e7c0b00138a1dcacc7901418d03a6cca8dab1856171c47aa785501ebc469efc5f0ae6963036a9f99569a4ed05c8c1533bdd3ced6d544b7252523aba8fa801ed125c64b040d7b12d1636a276da76430ffff3ccfd7d278c35807571055d7940352727edee7c618ad637c335b314950c9c4968853dfcab94046874a716f0b95ce00221edbbb40fd35d66a8f4b785d248244ab7113b52987851a6f8431a24629f6b0c00942ae0f0b4308c9906f876667b671034d58e5e76c45ac894853ecab8d07f1d8ea4489c46949ea6e4b92b8c8b212d418639db9b2e4900a720e9c2c1ce7fc892bf064a97388c5e31f5b23d5b3c83ef9c68777a5ced2962b966acbb53795893da9ffcda78bb1a3b4b1a770c00112b19d099e126e0c69cdace55c30ac680bc8734fc1dfae3a6b49b2bc2bcd209a7e3ca31c40f56aa8a5a0b65cc60703cc90d423eded893f1205b61f651ae20e8f6a56c32cc583097f187c2430a8b2ecfa680ff7c85c8b524a2ac045971b466270b7f8c3e5228c88a4ef10e31378d6b28a2867e0e6322f58d5817638220016cbace6440aa518427e8270a6e727cdc6afefa5f7f6c9a640e86b303f0f1bf82c4f36ecd292b58e7699d93464bb0cd32fc0df00523b35576fbac5cbb5f9507d2dc3f8adb280f3653c88c894f970b4fc4351d74092ab0368221c68fa5540f577b71a4e8398049a3bd08146317bb941448073645dab358933eb7e68cdbec1dfa5478a00860385600ee60ec4111d48aa992c0a9a2d6c30802eb9d15f76eb9bb40a01b32d7f73ba73e83df2f76baf64c0e99351ead502de257c4c2cf799797351384a9aa5220234eb84802294c7992c707e2993ede6d344930cd55287e3bf55213b8ad9ede5339716208fa3522a4d1f6513e7743f4cb08e1599925f93aa308298b67a70e9dba3bc74e8809e0906677b86a3d95e85df0d9604b12f5186c2423c90bf1f75b2037cffa23c792f2cf5b8d2d955908a1ab001707df47758a656b921a5cf61e6b3c7441b25494580c96e048dc95e7b88a863166a7a5e339ab6fe9f7a583f43157c5c51e68c658dd40e5ea22646b429247308bdfc5af709c48e41be34bb5d2f0e8e868d9b1896eebc2a80610122c87cfa95a6aff16d1137259d65ae87f67c04c841f5fbf86b7272267f558bd564f0449afe0d9812ebdab04e862d4b75a8579328a33749f8e9b44949f2543515ba394375b7340015e0d829c7a03dfa552c63a4e799e258441eabb0aa34d6b31b16817c25390e6ec61b5319cd02dfb77995bd9c60daea02912ef9ae43760ec7c2c32f7e1cef3c06ef8f5dec694b3b04f6b031e7b055d6e1b56d268cbad89a26264e712ee5aebb7e1fbcacae4f1fc329ea60baf0216d49fb9d03b7fa43c0b9749fba95d46ee51b5305f1cf6eda5d4fd1feb640ffdd83a995687d15e45b1b72463f4819b1a892e926bd92dcc2cb372c064ac50bddc24964704b52d6701e75a813772664bb02f4a17887b613891ce3d7887f5c9b23e44483b4ae60f4ee1ed252a32498d2d39c7c7adc2e6fa7c8a4b522d9b9f225bc0c99a18d98421ec2e2addc1bf32a5c351b1c3b39186bb47098405946d07adcb183815bbaa6730284fb3ba29bda58da473e431ec35f7134128e3eaa2464652c5df14acc77ef4980b241da87099d424ffb46f457495acab0e06e750b1b58036a31a0bf0b741c2d8b02f41704c45565167b8c41752a8d53e351b581824f532ce38b777dda89e5d58da822ed78dd79d12d20c2e52250921ec6fc141899014e1a9107d2831f99df93b04e3c82873fd99a0dc4098b54fcc189f692a3a3c28a326125e3957fe74a4fe7fda3bbaba41d1badd04e3b956af53f1911d2125766cbf89d33b9c1d762526f0e752409413530cb6c91c1df7c683b9ee63be7bf70c6228b109a643992279858dd9fbf3d87bb931eb4456236ccdabaa206c6512ca5cb267d436b412d032f29a4b33b27d5336380f83fe1c5c5a697584991871ca0e0d54214e31386ecfeb8422dd9fb34228d1ed1b3234429acb7f28e66e1d6aef7d18f2ad0ddd2801e50234c74282c82dd109afcd4dec183b28080f63482c59c2730ccb4483fcb3768563544934d3dcf188844d6f8ab6e9d880fbbd0cea879f9fc3725cbcfde2de530d75647be647cec2a9a52c7993741f97b3a0cdbff7f06012de20daef53ec313b9d24810135add73137d6c2df0f4199a27ddcb2c845e188eb3a345921f4e7512f9030ba7a8ef27cc6f4a241b7e7a64d3162a8429a720f7b76548e903eca477a71a426badcbbe75d4e3a4628b7f57f08262bedecfa1c92f884adc383adf8b35e455a1018641e98c8afa5f032c7d0b1a38e8210d2a156d8b63af29c86f5891864e3e47839c3e0225bb83d568fb7caddfbbfe040166c1bb95929b5f1923e2ab486c592e515ae13601fe675a59e159fd3e6b7ea895af29d916d5904283d886207d9eb8f0f8fd32f97bbe1e52c24b33405840ae3fc18f6321aedb0d13d5a050a9a8aaf7175d2bd7587aaeb0e147b0c68841cc179f55f52363f28961c70b2382455eb8df6b2e4b7af26db49763c771cb57cfab1a6d85faeab743646516fcda6f18a1178e904ab3c9e911d417ff5296671ff46be38dd84191f8a95ddb9ca057fef40d8e02c521fedd227de6d1ed5bb3c77747702d2f87a0e9554497b79cdf1c2bf32777b0009f6cfed85d7304d1101666c85b10bedc66eb5e9a2668772659ddde3300b76c534c0b36f27896d7fc9532868f64935010eaf102ad102a8b89ddc35aa54f07799c362699ef03a91ccfe660f5bf250e960b7297aa5bd1eb49b7ccb66d1efe5e51c1d315f5107801a0395a7ac9c3d08a644149ea968945014aed27ba8dd82a37ce466e9bcc2847ff3f3cec30533ac465b58441fbdb6749233dd7e220269e379bc7a6d1dccfa8468499ff05a5cc17730f471fb616000728c3e9dc1c2103b6917977ef44e4770b39de7970cd22439538828d1a49c778de03a168c2a6996c4cb3016fd1f8c4e3bb3be4ff1312ef74a726e23a3c534dbea45ad330bcfcfdf7116cdd8f0fa6ca601872040f08d94e31ae0331715dcc6764d8a9238da9acfbc63b83ba66ec300c0cb2ba7751d6c281c8f7a720cdbcda25bcaf878783031a8cad5a2de8925ae6766742e812532b41042d399a524110311a46116d1b62dac952249eab73c720fb90d0670a3cc88039444b0a8698078d0979b9e52f573aa0c28701e81e9d2049324176b45fe5f6906f076e852d116424debe6c1472cbe994480b470a775a4b304d03bab00d2e578acb4f824eabe5b1de3c9426ec72cd2fda00cb25d09a65c00c8ac9ff0daa1a0d522c3ec6e78d4a419444b7737440ff15c5650765bc1e96a029d1f68921e2f4cba52c47cce20be16ba95c4b2c1a48aa5c658cebd93c423ec6272908663a217d396aa902bf41aaeb5cc32c714ebf9175e815450f12e19c110eb20603a6560501293685da857321928d3bce05b5b80a47daae67875089517de0895f412a52a1a109060fd99dda5eadf610e6b9ed3727bde1331a7de18f8835de75e0ddca24be0c921904b0ed4685af161323e8aedacbaf28b8dc9bf6c0ea71d7529354e74c4a9ce7ee124cd09e211d1130300c1f07f282ebab12dd5ff9eefc8196bd29bd020b2bf91ac1ac0400d532e84d29903527a49dded771c3ca10611a8e3a6ce9f87a462c4c690bfac4c84e5b40f760d2e48ed80fc379aac2cfff9c5b473c2f024869710ef87d6f71296005c106b35a08cfa8a1822af79a239fc571ae58fa188e1ef7b6c6f78b3907750e8e7a3d95029a2d7d08c7abd65ab5442a4c1133dd49b69a553ff77be186afea7c1ce3111af62ee148df8e03a03b22b608ce81e8cf86743140d1985163c8e507fcd092a71972b5d685fd82339cbbc122d1a3d38b9593d5f13b8125d26505852eb1983cb6d9f67b9ec468945eea75106c6f16b6ce93f32f848a39c31926078fd565005634126f3d7ae3c0b71f197c4169a6435e35b922128b24f0b4ea8e14eef52802ea3da15b9fd369e6f4636bbbb0d51e3560fe2aa90f826675fad202725bc79e44da7d3b0db2a71fa5b1dbfedaaf6d754198e5ffacc75256875a48168b024a5b14b4815cf3fba37a0c9433fd87301255448003f986fb2281f21e1fc4a97266a3138790be6ca4e2f34adfbf1ac33a0a485609b0f8b24bc13b03f1ba39900f5e8acb1531f235dffd4631dfbeaf2dbd7dcd61386c2754ff9c45b78f1c789c9bef8ec854f956fc42c16bc9f9e8417c83070834f86a613ab894e642bd492547fe505b1687d0f636e167237620e7008195c9703e7b1de72888a622d370b7a58d13633db2e472240e1ee888f3a71013f57924542903c3495dc095c666c8a18bac8ae16867deaaa98fbea297c98a6bc048963e50f7ebd4aea41cd3b4a741ab748156f21e765452e50c8149a64db3160dd0c53b84d2fec453a15edbd8f569fbc0c553eab45624ed22a08a89b73a05bb3ba50aeff7fadd295e48c5b818377277e9ca3789742fe96854562dd50bab596fc043b211594bb6c78da6fa101f1858cfbc08b07a6c33554fb1d4402e32ffe376999d682c89b6187ae3c74eead47ad9ba61791b1efbb80b833bf329371441ef7c39ddc7fd2f46cee57df599bbcb32de43d436086f1b60fe505bf9169d8e129b6e8776ee998d204b2d917b3d8330c9c51642bc97826f27e796d391b5eda403aa0ee426b51d3768556b14b4ee0b016e089c4266e0a437528c6201f72b26349e105db914e247fbbbf81110296380f82097536310e7bd8b70dd64f6c2a76a580510588191af1d60063947f1e558d07f5e2a98031a7e7e1714e291ad0bd2f4357b9f5880f8f0780475ae57c3c60b1c592b268a1ade3a0aa1338a24df02fce13b12f515fbbaf727c6cc4c7b57c6bab4de8ea04256800fbc30afc107363b171e31955e0ba09d8b6233635010b3424adbfc0ca9b0462eeed8e00b088dd9e16d95e4c7eff1451ef90a9021d348b9a6b489bf718061e6849ab6c15d47c0eabc6c8c99777d10477560106fddda1211472d967e82c1718d201bcf02fd66ce70b5e661d888e758a0ddde23780e2ef1af76b40f91f0a33262477737a7e4584264c18e63b4ea1f97db284570d7047b89a041d8ce3be8d3b0bac4e69767d92b6f8f00c3dc4acc47c1a20b2fa6420de5c7c64f84ef17b04aaaa594edabb1d5cc616bc31e94036f6cd29fa94d1acd18ee100ef52cc41a5d342e797c794fef5aa8055360db00e2d3e5ba8d3e29be7576abed246504050e208bc2e08c72cc41b8411b72fa9115adb7747ac2392f13f07de83a7162cdbaf558600c6eb42387da616edfebdca4de152c2e081a198e5faa7ccbdc057d322abd24ab6b17276da37b8267092e6fa7032a1cd26c5b17223b9e649458f5f377e56632b2414f19e23cf680cce21f951b9380ea3cef0666f6c871c59345aae9c85f932ca1e53d98c6e2b16254b34e02a199784015c987550c2bca927e796b48cb03a6405d5d856a34e31336b1793a55e0ff0a83883de30b950164e069605533d6178362f0762fc2ad719729d7376204f34d069fe5dd8b965992650f5c04575332bc57b868459ebb79bbe980efe0adede3c910eeffa7e0a289db5bef08a61584b3756b463600153e821f8e8ca4b04ce8eedd916cb32c2256b6169fa1b4c9fdeb31fa5c22ea964bc1d17ed79306a65aadc91235e434c6e91522cfd3e9e1e44fd176e9478adbb72ca7f51ee2174ec14cc9897b4504ccf8659bb9ebb241447692b1ed6b34527254147fe8dc282f00663e67edcc41a99c2d308ae3ca74c0fe40037745dc6fb7251e15a2a770c97d333be859a42120ac97a6154e1a2d211d321b1aaffd765e137a9bcd113d82735faf797a69c37a949b6d4f78b80ae99951cfd062bc7540131181e51cbfe85d745df77f7dfb7ab408da9cd974c243619080055c5acbdbb779e2ddc517a91fa77c38ec11c5352f5f56a230bb0aabf5dd31cacf6c906148f1ac93e6f736cf40d63fa7ec3267cd55fa8f2a69277bf6212e3cefc21b6f6ae1cf424b6d27df77fe54ed43977dc1e3293947fa41603fc367e787aeac9fb7a6edf15873af4b3de9834653297bbe8de158fecfa048f91bc2cafad6cacbba61d8fe6e2fcfff3160706e3ba2e46daac7d9b5787d7b74c1480fa40e10478f8a776853a692b131eaaa36d25e363728fb855d0f8d555903c95aa21671a84bbf9d4f69363b3f4019d4edc474f450f1cbd6664af6f67a235e5e5471b465874a08f9ba9e87b61fe9685851ee39f0cf9c29ce45d2c4f6355f29ca520ab113de6896125c9dfb5f46463ee4c0362cb4bae9915d3537802eb4b13943380dbc127166d475e70fad8b434c83a2e792701aa43796633f8195b59bd160e04b4aae333b423193a36ea4c39dc068c9b698a6ab3cb18b0e55bc009fa3c65e1aa2efb5a1f8bedebe8ac693bb5cdf317aace77d2ccf1b602e9edb1aea13c7204ec3bf766ba9196f4332c0dd61f790cc47702338e012c15c7218ca73547a3812caf606aea10b42ab5892cfe9089335a750ccc22d8745057743be23e8001284a8b68286f93dd763b800828aa5bc92094a11bf1048ff11de1299d4f77c636496ce73d17bf4280d0882610540b00bd7ac6dd4d447f71df521da18b75b8f23503761ce3a41cc3eac7650dbad648a3d264c1ded9ba058f51bb13766873a0cb87c49d723946f71cf3cf1b30c4802946bfd58f1db91a91c65c8f2dbdc84163bbf7587318c56aabe8214f1abf31e0ad18765106198d55dcb7c1566935a781c9df931f7776ad2ad485be81c7410f1f46f1a101060861d46f425965d0cc4f5f8f29ee4f18afbaa4a496c751fac03167d6d19fc86416700aa44fdbc4d3ab24f755a85727588e99165fb8aa3592a5654b46f3be347188c12ab1b50d38bbf2c7ee6157a2e3d62b31674914a205c057f19d6d1ba932c0a7f26c8e1a5e40ae29465c9ad52209b527aef764f71f66ebf45edcdc2e171ddc304bbe36f027e2c3a44076e65b33755941b545143348c327f5f3f53deec93ec60a407d2bf63e4e5a2d9e563ff67a43a9db2fcd91fe908400dd18f2bdf70a1c1415d1e699b5c08fc5f8032f553fcdcf94bed1987d4f7fb5f9b05c0f09c0f8b9eefbf6515187902e1ceeab3f6b59404f33a6741bf22411dc6680b33eb6d8c83aea7dc93ff3f4f6ca2464d8f70330be25167573c5653f8ecbac636b4331fb538bdf3b4243224d97c5dd8fa398faabd2caabbaf7cf332b92b082bdcc857cdfee4c3c0d5767bcfc8fa380e164dcefb2575b45bb2d752974a150984409b3bd799933cfcb2d1bec1f113759358e3b10a06b504ed686b05fccd3e3177ced1b289581df9b9feb72d04cc2717b6f770c9dd4c0aa8f684bf2911203bb2440504bc4f0f4ad8f86b387b06c40b7a75be536cdb194afdf83fcb02d9602fa483ce1dc8e08e5124b3b240c0e4531fc089583162b79dcabb175408c7ee6d3048223483335160dbe3d8059b63cd579a5bd71fe50ced45c69c79a150e9118a5bff8062f55fb097b4b48779443ed80e1c9de713a37b39003adc1017f7407299c7bd50e2f307d7b9f01a3458a646f9b1dcebf9ca4342dad7b8617006c8c4dcafc4b15d18faf1cd0d64e1669a76d76a2f78f70d2e367663152617714fa22746410c0cc5066f7a8f0c3e50fd61b3c4457c0b91570ccb5163b3e5cc9ad1b2198aa65d21e1b45efe2ceed0aa7eb9e4ea4a8fa18e9272297e063ccd7f4c8bfc9a465020f3da76a0d213e3f896c00f82cb14c48b7d1b0248ed009f2047783b506b2949775eeebe994094572b702402bccc466cd096d31c1d69de9a0aaed6b57ee52bc2f0e9ec394554ef9272319f1f0c4f5011a245f45d572f11ae7f9f1a597088451bff0e1fd5ce3d38880d771a819642a33434830d2b5c8affe06e027d9aec791245d1ea0313e5b9036e74d955aae0766b25fa95ae080c643578683f1251e1b09c841428859c80d5d073ca4e8f50497bd141ffce0598dfd1385fe81f38bb08edf03a829cba53e05d215d832c2aae4c1fa20b9bff88673c4329bd5d08e8e7f3416e5707dc8d50f690e96e34747d961e93e05950c0b40d3aec666139dd69d161aa249e734afa587aa5e07f6a0cf9404fcd2d03c87f9e778006bfa0edd402b92cee6e0b9575239eae9b6c74c91bb5f6b4c6d4d07af7bd5c1f8ebe750ba634333d4efe6ed75e9d521d601f247ea811dbf09cdf75a109ea068308d5572f07ea5df48aada0963cc2d7ddc4f4f243bcc7055574bd4b403c91b061bb233b7386973301452823d022b94b82ed7faf373ee6118c9ebafc1222995c24e012969fc9e8ef62889e4e2eb70d956e662ced4198809dd97942e2a81117a5798af4adcfe3dde6f4ecac11da17b47c23b3441c09efe7c037329d194e47f7293518f9279cdee4d509e8d76140a9329611be66bcc2440c47d5322fce1ecfbcf1db959a74258dae62f9ec8d7bb648295373ff1934cbcbab6b05789ef5c3245854fc263e68b96df2afcbce73b5f6abd2d786dad5b4b11621849b40d437ff614212371a78205695758520ba6953ce8d717cbf249a96fb87b2563f251bd32ccf7d18cab18d59ef89442dff38d9d50c3b833d49ee07858e366fcb88e437f7bf21e1eb1c17705a4eda5ea8402b54e2d9811b731372f002f0b4f9544053a1439baa995dd46892527dc0eab27814a50086300f7e44f8afaf83286e6c9e8c6dae76ee3f25cd4913669238cf73206d20aae576347d583a391546f95d208983f979c4c044ba1c0469d1ac1be36e3a75c1317e93d592421d6f3a036800008ffafb44fcc1e9327a117a2b579f0e1b04b666a56020d41de41c6a8f59c5b318bd49492d1dcfeb2dc4ad3cf232ce06e3a04d7e66cd084b5c5deca4a7c34bf7aeb30a7628ab902698cbb7406655c4f224dfc464ba76e5a47f23629867b273496d31acb770daa0e897330bf35cc505fa9f4ec441f0d8bdd870c59e2f68c43ce91e94638203fabdda0fb8caf681760597fc4b0832f9b05c5fcac4ac88a302ec3eeb47fc02fde6d813fcc52a8dcb3189f13165021813151a28311f359a4aa3d2617626fbcca9a62f44f0e4026563d333f1d72050bf3a56853f432a4654c5f2f5dc818d006d422ef51c9df0005f22b7d5e51dbcfcda8823a9ccc836312e98365a2465217790a7afd857dea37adec86a7e747b76961dc9461a1e6daac9b6ad253e7b1271e31e74fa4ecf9707a2fe304fce7aff829b7d3647c2cda641c28d47eac7a88411b4a1c97ffb2574900730d771cf2c4b73d0e5454091fb0fee2a0cf1d2cb4c7a05b7563b19206f06ac9456d8ffd8535bfb51d4aadbaf62aa63d802406933cd62e753b2afc4857eb19105a764aa13d5ff0fe93144d9c8fd47fe7248e2f1baf385b8a91286c6e4913ee4a06ac34f538b8457c97acd914aabc1a88d85f6b989c59df8a4bcdd787cae6e450123b01ea62ab296cef3e0eb8478798ca09654679f5b399479498fb0b9ce72a095a90b4d3cc5c46a8352a11672cc6ba9954016ea295a278c9997b206529c9a6f4e92cef9d764bb9d5bc869f09b288a2daaca0f90a31216fb42319e159ee7fade638cb1ce12e25c91c76bf523ffd79397963f83ef8c243f6c4e32669aab4a00324d16d5d1f1eac095a1fa6ab8295581a42d21195f2c371d6554af009bd0641556d375f2514e42b5c8275fff332df146b4ecbbd05c0680346094cda33c7936f17058d3d55133edd7e80c6dfcc3fa5bac971a8b0f25d6920cf4eb1fa5ed36cbbb452b07406689c57d8f618ecf82da4e8917189a7836a29633fbe2b0a95ef3c4e3cd9e75335f7d0e63f197465b683f5e92dc6e177bf84797800eb87beedcd2399e9c38b4a99fb44561de6afd94d323dc6e520e7e8133de57c7710b86ec4acbd429539be13c63abef77ae43956d385c8e885b00c9419202a771e73f915a686d04b950d8359d0e35a6d4bb63cb559478ed1ae7825b42b5d208f3b13bf99f7cd263e569a6f892999b3c302aae002989c55e0e927d27fd5df102d00939e2616934c5d1ed3b0c706f24e34fc55c2d14a933abc316804b036d78fb658184a1c19b9ddb33be14aab91bb73ee1c6e262416ff8cdd3420b491eefb244977c8476aa7c696d14a8ea824ef4391a30ed4f30a424d39548143033c902a46ba4743f9b9fc095828370537ce58397c77853221ded010d8385f12401d9432eb355c17918fc38dd008342e982cc50ebf100a37b3dcd72e9c27569867374b7012422223e4d47e2750cb8f32e5790dc75b499f0c5b52830a76c2ef43faf8a6ea78d5fbc320dcb785a11769188ca49f64b020510efe716050810043f7d336311640541ae284e029844313c68504d45a7dbe416a2f19952938e8ddd97cc2285860e17e3e5a90e961dfb1763f3c39caf7999b48f54970d23c6cd10a105ec275d709cd5bb747cae9df8f6abd30c99d8b4ad404e783a63b66f4a9746f6362aa6f4d3dcc468fc5a10ce5df6a5e9a5dba32a4b3506c5f7ee254fcdd6f531b9ea2a6bce0e4754f1d05328c99076986ee210e76eb71d5d94134b28275d4601a2d5adadfd98dd06d8ef144d057027a3ce9682c9cf45791776cf3329fe43f7417523ea5d16619e138e9edbfdc132d02d2866d1c29ac89b06075215878a19ae765194d9f9d3a78b1615e43d56d7609c9d9d3372c5c10b793c4f392a4e47fb96c29d2475b73c852ec4df24446ee6d12ba0f4b8417520e2fd26b32bab3bebe1d625226474638969ece06da598fe3d6f833e1298bd2169973808458b932ad197884cfa14d46996d9ef215141b6c67d52f8da6d44641a12bf3aa57fc9e09a168c19488317f747ba9de30b4c909f2c4601404b475ef3598044fab740c2e68dc4a0012501b1262b5b9e0d9c8294034787f749d1e4d1d32a52c52ee5d87f9e490637d9411bc73f612a7cc8a7b68df78788a7cf9c923cd883ebf12a5d5526b4f4736a011a35f6dad3b36aac8afa631991b1f5e0196d2d4db93a9c301f2a8a69cfec4a586974cdacc28ebd9eeacc85a31805693cdacd3ed8994e3fb4824620437f464ae0b1d84503bb9b4efbd1cbb5d3800d756aa7f840e1f997da34e2ef39b85356b569573396712ca3cf7af2868f69b0017ce34f88c9c692bbfc599a567e0b5ebc7f137f0fb702b93377efccf9538a982719857f64affa66aa154e078a48bc5df7e990f9523f0664f1b9166e8720307b80f8b0ab8c2d30ce2d1d9f32d345dfa1e4ca35208ac4163600ce66c5be99bf759052d5bbf35e40cf9c62ecfcbf21ce1d9560b0d5248aea36f2e64c1bda4c69c772524e083855f487f46572cafbab497caeabe7a405ceb12d8d38cb6aff8828b3616e88d1e8e6af7dbcf44676db2951699da9c0f048356a0c8ce8f9deb7b2600022eb2b4cac50cbc414661549add5dc01e6c4cd73a08fa1cb6f124a59042ee269f7f331b3468e16089df2c89dc78743b68c1f1b3151f87877896eb92d936b573dec8fa178b7d10eb2072efe85ba4608e28bd7b1791630235b445d6335047c4e105ed1bdb610e66f8de5770a32b89a0c3a5a10a5219702191152f7b96bff9d2fc12ac37af3c143042aa94fa068cdabf016d88a6f209ef4c3615cca70c743be1ee67eae9d8748e61737f0a0b0aea1e37f31279f8b6f8faf47c0df74f5d4756169a3ed282d5802ecc469c8da864e8eb1d4ce3f9012af0a9032fb782a7a5613f429c1fd17a72aea055802f042d5d4e6ca354e757a1a51ebd8edec4e7e092f6a7bead04a350b5e028fe772e80e7e69d65e532be1047aa594003cd7426e4511687413deac7eeb80258435d86e32b828aa9db5214ceb5aac77bcf42ff20568baf1e0b498707bb4a86ab948ad3f7ddaa2dab2824b5ce1ba0f81dd574401e30cec295121455d8ad9c47b912be5a0c98be33fd6c28eea1f53831de6e5f3e6c4498fad71b7ba2ca34b4f0d759f9ca989b8e790719eaf5b80210fbee303e38122e0c58882025c6f21a7be0c4962412a185e51bc458c66e6cfc4f2ee34a96672228708934b7ee3369c9a7a768ed2750afa40e4e21a8ad8b4158f75f50b47e03984494402a93232d3d109804144a57ec5eabecf575ce4d46473560720ec2901396d935a4d5b988dde8fe52b6757bd36bb3cfd79e6176ffa98260e4de1c640d04c10c13c891186752aa3bb04fd2e5f8ce612aaf2364be88e0fd92c007418dc8fa35f3f0fc310320a9e05e50a0bf5dd27e6be3dd1edd0fe4cec193c980c976de3b04f1ceb48234be5781b2a50f1e47311eaf92a562e34d979d5021082035a24d99f390d754fdccd07324d963d2465fe6e9a9adfaa97e1a50bfd4cbe9d096253464f49db","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"8a01c5d3519b99bb5af51a466587a22b"};

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
