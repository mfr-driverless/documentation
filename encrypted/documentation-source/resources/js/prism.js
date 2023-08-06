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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"80606fc97f3fc5bead0c5cb502ee4f3fea79c2693cac1508cb33ac63414253cc13029f10cad8b45ba2a9605066b0e5377c009da65d763bf2eafaf1616d7ce8b0c2235bf45c9c5296df1009ed12a1802267b1bff396ce3fcd2664aff573de8ff59bcdf967b31715b01fc96ff09e96c189e0df06b7d82be279954f534b47f10ec09471054c69b165d22d073669b92e473789c90ee67ef739b3529ba29ee73d62bf23c3fa9d5d925076e28c178287565a010094aa1a8f1fd4c3ab7bf066e292a66657345914f344e27838f7d20110bfddd65e831378935572a52bfb18ab7dc92715701104c0463eafbef49374944944e681b43af043b37dad60f9af54b8a6785c3d0af4884ff2cb9d0c9f48db9f126dfd69ad21189083cc5684fd4395583d44b5d493acb5750d84a0f85f065e41c598775006b6007f1163d8aa09afef5815b08949b98c584312d2d71d94996098e6f75aa50e3adc8e4f5d20bbc9096c5ff3a55a660559a8ddf493934d9aa128465f8ccf1837cb5104952f1a5614be95c429e9d8499558d6a2a652ad6cabe7d85e3a73abf343f9db53ae50f899bbc583cb9b51809050a8186b725db967b57b3f1b1a1916e5fcf53fed1bc7e4285771e84d0196ae1c20c357e6790596a6e2449122772500f1e3d25ba0f96bb0a79576f249dd0cb561e5207928f645a73f637e4dea28da77d3baf2dfeef1674411483b9bd12c761324891a078e3086ea900ab53b7373aee4006590a17f775a95de59bc36350b4bcd23d13b694c2e66fd44e559111126394dd70e50c241fe92dfa078609378554dedb96a498627945c42b8d09712077ea5d3024c15a8dae8cb9a65f7786b31d55cf9b5a259361c1590b9876f858f6ae0bcd18a70bc1038c4193d544bfc1b966a53830b98a30822a22db1ef7de30c71079c63e2abbf0446971be287a79bf47807229eb95691f3d7422cb46cf4ab4a143216d0f5fe697888e5358aface599e5eb86f1b807574e001c3df3c17c9150954f52187079844def87485db35f83d9c12ecd9ae7cb3761f0fa27c1dcd4318ce353131272bd8218044d920280da2d074846db23e30dfd7c9c8b545b90721d81c425c92e21278ae805e242a9d20c64468f7e57c16c2754198b7219e9bddb52a037f5f29cb2b58e6f1b80d0298a5619e97993b56b58e8a22d78e541f1dada29b75530ca451c99ed2e9817030dd1b4b3932f831247b5fd299691c969d5a6b6a6cdcded8dcceeb589be854cba2ce76aecf0feb3570a66d20b3235fb941697294816b88bbddf558bae4cd20fdb8a9bdc1a1e0646c7a880d485fadf3856c24c7a0e951ab1c721eb27aabc0e3ef470d88fd3e349a3c8c60bd1d7d4e4deb0ed0a343f76e3ab1de1e2957c924174e82c8d488ee4a3e411279565436d9530d0d8effab9797849a9ab85f969d41b038f9af318a6fe8597e6e93a119516e453d413559533a5a1310782fbdbb665443aae77927c4fb0f2bcc0c95f5d796b7835fe20146aa52943302187139ff8575aa33c88e1072dd2ae9355a9b1a444077a853570ce06596f3b7efec0a550fc1f592d282e8070e7c11f89ffb4c4f948ef533f0f05e11797c6c1e6d07709b77a77641c2404f7ac730f25e7e7143f849b4f6c4b06176c0cf7f629a7e6f078039f8a21ec998754c706290aca329ed00e1f3571e8704b752a79a2db11811622be8f8a297aec6709b7e02f0f9b6e7b690b1c2e2907d86e3cdd072320228a195d8d8ef5beb39752cba53d0741633825eed276255d392c15b27ef16b9087ae2b9a6486f322407dd28d532bb9c0b121c76cae8b3c6d69df65735467b0ab48ec43c06b4a087cbd6fcf8aef5fa0436759a1aa0ffddd899fd5076c7444e1d0c387ec076834f0c03241dff42547bed18a69aa466a6754757d9bf8ea83888a5eecc6367baf011c85e5688952b5a18dcb51cb744b55200fda15f8ca98e38cf5758ada6ec47ce5d588584678353e596df467d42a94da175b24ea35aa68628648a5a436449d04c395da211722fa8606a82a06e2eae8f5361ac4f4fb880c8a2c0036fcfd523f89249f3739ace9c8bd01f10f2ca69c4b06044dc60c12ae3cd10abad6bebc0336b2abf119da6b7898485744ef3625d3c87c74cea36e375f5e135016af4914b38e960f79cf2fb26e72e0dee50a1970e9945659559e3d0e7612f4779b89bf3411bddbc2fc7e55964eee6305e11ba1197c338d093ac5eb1366b9f3907c8a6df0b379b409860c00a6fbd3bb1ef69456755a3d4d84bd9a6020e405b0ad11c579a88c0a3a8bc5faba287888ecd46365c36d5a7bb504a78a23bd4423662d77300f7a2d608a2d6774e5d487d83cb347c58c012d21cca996400664f0a225d02af9b56468e2bb446fbf6c6c6235c069d4820f48531209eb14a6d5a487b314c257fda733543012e61563209da9a506530ebd1aebe4fd406d67d0322d5544b9f018a657d6227e2fde17e6a2790e677292de07c36bd79a65f1bf6eaf1fc97a55fa0727bceab9152c2eaba053c9fda9fa2c13f5d3d11937c5dfc873179387c0f0d57a86aff839500b607e9c196a201b92b49213e91d9056697d09d4ad06ce2d60e69c8328eb430368e75c08a638ae61b1b01548cf8ded66853389c64958453110761dbe512c776d8b9eb93db6a028aa4dfd6e4bea405a4c51d4dd9e51246d7a736234a965ca026538b324b8e2aea8ebf33c7f8b49cd6acd9fec38134ce24afdffcb14aebee1fccb97880bf94b9f45b16f0ecf5d156ca52c963d975b2499fd4c61fcfbc07294f3257c9a8d535de5136eb88c3cb123d9a106376dca3dd748d41659cca1a87494d0e0a8969a13df71f670259a66ef2419e176521a25ffeef78adae72c4b08637ac867344b0691c1249f03c3318601c1c02aadf034464aab62b2a53958a7a9b94f3b2fd039b9cf88a936f7dcb237f0008fc411cefffc35b9078ead8f4d4991ba50382af2eb0486709707a89e7f4f16862f6f75f18434447d285b582d028bb3f930ddc2e322cafc7d7c333da6c3eb9f819c8182a7a7ca04e046c24834b7e28e264247ab942142520a21b6b5d1534647d5d8840d4170f8ccae0b363631d3ad20f2195ed7621a37f2f0478cc4619b4002c557fe7f2faa1894ddab61db65a62ffc586e0240219c72cc5ba83e75914e014956c91cef0ec57a987c9e76aa74d7284f841010b3b71257d2a7d5a9e263544ab59bc58f08263d75cd362d01c9efabfadbb0098785fe59f447ebc3d076ec4570bbd293b5b7c35d464e5a252d168117c2c6ca6b8f66bcb9691a3703c0dbf970a5b035e25de54b03a72e5240c9f0a092885e61a2f1214a51bb252529de050307c30f219dc0ca1ac460bbdf266b24b35d3392b1008e292246597dd32e3b9e62aaab6cfa231c5c0d0e9d2a8aa243d4e25f9329636d45da3f5764b7142f03854e43c998fb23431af2777a61085934a4777dbc2023b5059efb96f0b6d4d6c5b5dba666680666fcbc740e20328a32d96caa5aabc7fa52225c65d14f43dc496e5b4bed1e88c695f89fe3de982808c2c8d58d01fdc7e4e95f17dcb2829846f5f404e39425c31eb06efad22eeab9df78e18ea03258332e6e2a6a18c54310b501a5d14e2a7112cc114c669d4a872023091703f3b7652af3d760731ad7d50c6961ca6296a738e9173c72100478fa09e59376818196f5528d34fb07576800117bccea0eded23aa7c7f945fefd2ddb7d72d28252d1b5a86d10f0ed18be64276b73329230c2bcfccbfca31240ba1f6aa3225455d25e9464f7673ad62750981440b577f0ad568f0fca793c1b784f3ae057614c2f701173c4fdb5c0b3e64f494271931acabda2daf9ffa0f353243fc47edc335d722e10551f7f998ef03cc016125322ea021865df6f92172964a1ac034d06ff34064d25ce59da36db7c42147e9b396fbf2545c4eabdfa458dbbe657146b2759a69bdf760285f17224889ccbf8381e83da71f0c7f8b525a2a449a9d854236c549f235668610f2f671ce2dc832d16b3a535bbaba4361cdf54447e156247a81a2fa1fd2c4cdffc30773b8c414ed317b56b1745269b5d7b13084fd05e75b7d7cf07d2484369eaeb16e128b03bbdd659d601b21d2523f9fe0e80406e558ec993a60a7a937fcc164356c6ee6bee695d45fdf28e166ac69580eafef076c07778f42c2fc9e5dc727a6c96e4f9fe42e64e1f2be2d1e3df8675a662e88104800ead58fe2f4a102c3fc1ef7aa1ab49c10284dfdb3ff360233d2e340d7d8507e122cfe442f1a00bc6867535c3f24ef941d8eb8c3f3e7b758c2b175f5f3edaa4846be52a95afefebe8e634eb4fd728e7c02a3148b3d8afc39fb1ba1289e4db0efe1681e3c600701fd2fb2acc4fe7ab1bd81d2689e06c2b98b2627105d4db0cffdf63cb61ea83eedbe20579952f496c0d351235411abd0c199a246e2856521e8190876aaa157d1b0b6fc8bfc3885740fcf3667383d42bca438efadb7c8bd896db27daeec7340be6c66c6224feec684ced376dd6946a33b089ebb785811fdd658d8ebfb4a332fdbb485e4ccab362cb32c4fb6d333fabdc5640ecc8bdd8fb9a4a32fbebb4d296437a429ecbd3c05c6a447091e40e9864db3ed07449998e315a9209b42f923f5d1985b179234f222eac7a128f8c7f48e92471c43e12944367362c718cd9c59013faf009794fac3cce5ffa7f232027d2f344444c218f0b08019ccc90116aab5c0f298d28e39e8e3132197a153eee92ab08a9b16a1659d6bd25f1d22ceed935145fb1355e84241162a6d4d0790beb05239b802784ac713982e0ba0a2d93c60d5a6e60c11dde9412b0c22880907214b0dae212ca4d523e1708d0eb62e3d07b4da79bb87272bc94e95f9a9b402e42f558120869c19bb1aeec66870de739acf814c780bba0d6ea01a18aded5d3a83ce8f830a9f6dbbc268a0b148eaaabb5ef5bddf64019fe9d9516d620a62f0a25bc21c834cf02163cce3514dda3b24dd03a0db4fdcda5f6d77a4d368e6c571857ca06cac8893be61f14989a81ac858eba4bdd44cea23f053323fd6dadd3633995f729f6a7eb90288b6144257e59123306d791cf05fd200c7e780b22c0683f76b975bf352764de60a3c5861e652e84ac52650090390547af4d4aee016fac1dfeaf44e7878a82bf338547631c09c0d31c21f309fce70fbc1064ebf9845d8601a8e38ab989876ec4b20d4ef7345ad577174b1b37a019723f2c20c07e8c0a5c47a5eb0fccabe4ad811527fee25062ff77d43b92c62bb5e61e203d9791f924305e194ba5d1348db347c9a235a8a43112401dc2d4c104c3e1de04b9f82f524bbe33c574578eacfdc0702da6ec3bc8c854dca38de28192de573e6fbd101ab77bddba99e6873525553cd8666c79978f41f6526c3648ecff6693c6f1ed5953fb2bc106b72e11ecdf48736bb3b01e00dfcb2d2903c8097d42292b9cdca9b788a5892d1ecd487eae64568b0d26e5e5c7bb964db130a892390229fd3bed4674b34501796daccfef608fa4bb746a5bf5f2dd7b6f63e161f27fb00a3d2d8ff38f683d09a79eedb7698564633587af9066598725bd177dda5bf8efc4dad76266953c09395232da12999eccd76b3433145c3228257dcbf3575f17a3ac229d153b46bf99ee737204b667d7903d6864ebb2a19ed6fb16482c6fa1a13e4bd0216ce118134210bf92c61e06e309dc263ba3754d18c041d121470e62195cfba1891d62ced46a8ed2b3bb9b91e2ab651709d318007e8e1fbae93254176263941bd9f0f4584f3d5f4e57cc0c601c320f14b6892eebbce5ab254c36176926f203e40e04ecfc5578d20fcac02e4625607f4c42e32d4405befc2b94e106995e04564996c20433ac3a9e32774407a9238fce7da51373a210e8628dd88460c3446078f52f0f50603942c075942fa4e644efb9a2122d72f551ae2211ba4b3084a6a553195e502e8bf3bbfb91525d9abb57e359b71cf7e22e804d59b93fa6e8a4e2428ee730544c3eb176293b1ae6ad73012cf3010e902702116f50e821c2379a1bf749bd5a9745a07ff813aa37e4246340f7420ad4ed323fb87c92076f98db36c2b8d936d0ce31c6ab79a2177289191e5c6e9e595fb2181e142e1cb36511d361639525da1f50a8fbb4cbfe405d177d5a2dc66787c7a11e2b2800dd41f5edfb0163b9bda641580f4b7ffee4ef5a0b829ac9e815b512203c6ec6d09ca234939e2514078c668f0e71d6aafa2733bb80a0bb69a6ba077ce6db04ab797e53f958275aa1072a4550892ce6f3dd7da752b032f237e0c61eebecf0221c6cd28c283a979538614a54db11fe9813c823126d0009052e9e6027eb33ed02a9316a2fc1fdfff1e3256969a0129565937168ca490de1feb9940dc2a433dde2bc56506e41c07e2a11be7e450bca20045096c2bb7cc5b3e39fe34bf708778dfc73078f5fb48fcbd22890ef847f09fdcd460d891c83c0607d103a0604d9d5c2f3e2f9f3a89e98a9d8bdbe5a6cab1729471a237781f56484806816d9a836d67b6bdeb0e5e460b09216cae5fef4cf78418d17b40c921d01eaaee3447321b14fce2bf96268a53d4c25e41bd032073acee8a5b701ca265d95ad3654e49bd8cd4d41f4fd6d05af594f19b647ee8ee9f01510d40a8f7287091f65ba2229424c8f47ff9698f76312a3f7dd2b33315d114754d5fa1d29653fe1a87d0ccd5e5aefef7874996abc47489a2e747444551003a2dde119a0dd6879303789757c83ff3e47d2d4589ce9ef4d5e3e9c2fc020de690ad578507a76361fd0f70bd60320bad03f988e728159859b732a8893db4d69944be038632e47d1797a69b90ecc4f6083f9e45f4ed9fa12ee8e23e4c041ee23f8d57c7f88a50db8a74f76131ac8f0ef8b584ee5aba88dd738bc5054b340565cbc52ba9566d5e9c32d166b061d69da82ed10fac3700d4a46f2ffa648802a073dc67f1a4bb2ce0896f30a9a916c8f202769512ff3f42923b7a90f960ea69d846b3ad5bd6d1c33d937755c08ef2f9f4cd10edb5ce9a6695eb1df934de0a0445a86f5e7fc54b423ceb8667e3590fac29ed61db2e04378f567a7b2ca22f5dc12f268ea952023dd16fb76a0cd3f74c2632f0a079b99b072b729b4ccc030da4ad6c5c8799d81792168408a60a384eb11612c77bc93adeddb0d743a3ac7f39b709ce018b4c0c295bd1088c38224e1f9684205997ed36edc73b34779295b9cdd50ab0ddfbe8c41f54dc84dad1752df4afd2532fb5c5463fe91fbd84a350209469569af6672e9d06969f35e46043d851a9587718ba13e15272d95dbfc8342ef7c94e9e9d67e6e9393474d31748494f443b3b738a860366abc12e7d55b8c5fb58d42ea44792d1e43088c634b523ea3d9cc68aaf07c9928993acaa345ee2ba74264ef36c7c2a1f5f781ad36ae986e16bb1cecd8e02ff24bb6fb676056e036c287c0591fb134ef90598204d550a5e2200bff500f2238a6515aef31afb804a5f58399fcbbd37d726e058cd8f2ff92a5bdba69d3e1c31e7e0dc07845b41eeb87f533d3c2b37279b3b5db8478be6e4712314e65ae3d8f7d8928954a3489cfe9f2d41df89710478cde4c32532d5ba5c0cbce942472366d676cf6af218f0e3cb53de5f5c65d87477b11feae214596b986a8ca6e0bfde811ca790958ae57fd021e5d53cd971dd343c3543afe84933f921cfb3ec82441a6fb1a5025decd99e1429c32b6488e05303057afedd5676ac44de0f805dc2da9e2ab9a4407a28e271e12a9259c61014a406b617990ae5a4bd953792fdbde780a85d706843898e3ecdfa88f0477838f8934cd7e6bd1b4d24f8f1ec8c7c193958ba3e895eb33f2b7938c0cc5c83f938e7037ea9e8b0c52b6e72917f85412cd2b8e80412b76a0d6f263490728fd5cc231a79f6338023109767da94677b0ff9543ca8c02730c5cb2d03bf051115d06cdf57826d8927a501257f26026d88d860aafc1818404ceefadc8755a763980722f28d058882f206e05fcd84fc51f2a49d32a278fa6e45b40b33cc6821ddbbc5fc3a9c03226bea418f7a684d166b8676be3c9fea4fa6612002e88e86ab6758e98ce520939ce7642138a27106fe30b1f85d5f9f04c6abf2c25a0895d069eee329bec4468b470d2b478b8f185e70218b465f3d42e062c9d59efbd00562f9163668178f41f679b859c08033ccd75c7d826eb84f13f146983c213f1a030e5700c3e0cba3d8d2461e8952a96e82704daa2dbb2b0c042e2b4e88074028328941a97d6f97f18be7b41917e96be11fbacfa7aa3dd1042ce43b267d50549d36883c92bc40aac4843c0a37bf3561a709fe7f6c6b9dc8a94fbd4d219e61c6cb2436289c8a6c8fee5fb9629587e112ebe1c5f86720d722e91c452c44f75fcb8d15334cf2865a58e1c6f51bcfda0487f57aec3296a33cea71f4e50493d5f5d74300cd0b55500add62950114bff61f7c001c45f9cb4f552e9b4488cae06cf222281977fb7c1c242775ab38bc2869af09d553ded2386e8d36372947164f8718226549d0c35ee39b00a123b6a8361375d3359cce9e8c9976c1d7e9949fcffa91dd6fc31ba840ce097674fd2d99ecffe002916b4a9752f1299357588f43c8f9a5ef5dcd0dd2a1e074a5f5f489503a955f6a53c238187f868cba477c6e6715276021e06acb2608113b34ad8d2851aafc059f063ba3ae7de71e9bc5bb876ce9633df1cef35a7302178bb65ca76c586d8aaa9420f8d1a4108e693ed6c865a8032e53b5a867edf0532ec5df0d5ff90682f9b9ab9204722897e4928a8dd9583f9dfc8f63e40503158e3eb73741eb4d06d136ecf5fa1b6123f8e80f8b8f038e670f074d94de0f6ec0b3cbd55261baa62bf99150e4168e74481ff944957bdbd15d6e4b1dd814e57dad3925fa26d9d73795c7e6c0b40a429593b7eef7dcbfe1a403ad0e3a0f2a14900462c84c440d636a12f16833dcc835094f46276ce604a65014eeffdf6bcbad4612687c2398db41bc6ef4a06611523ff9324711f4f690d324e7d62aef6bd7ed5d9afba1b328bc3599d93c0f4b2c3fe3390a5ca18d0762d04196e6ce1268dca31d09434076b0c0ee72f98068b113de4ec3c62a0f5069cf06a9e05be6f6e8b21313dd72f95884b7bd751eca6b71531e677bddf93914fbadd9973982eca289aa237e286a5678e8c6e68d1a901a878b78e17c9a48be9895955a9a78bb1aa5a1f9d8c05d002f790056fd21de0706b504ff57f449296a5b82c453fd085e83ee1bd93f883d414da110609db00f1726798e6979b0d7a0f8913af98b7d00789491f5dae88f934b0987c61fda1ae365c6cd7ee6db139c45e891daf8174e0c5d0a057364aff7aac1a6eb6dc20aa5bc608fe5d674e981922045fb77e8dd1ed55c43e3ff218e98e5f8272d6d38e1030d97603bd9e94aefb488a1ec3e1f9a278dd4f3021a6d254769cc1f7938b585a33cc19e56a72ae31b98de429e91a2beaa191f5eb237f4edd20222d86f4c897f10af6b0feb62c3c955d3f671b9c41f7b62570ac4c2ece936f6fb9ab57d93be9411e619f6baca1f591b043dd456cd8d58cba6aa3aba58d1083433a4bc4d837085b6e5d8e70ecfa6a0b3efad6f4f621ad39162d449f9113ad0d6b52d57b7e347992df7e449acdb29023aba0700fd9d988856124fb58faa08ad61c641f3c698e252a16aa609102ece87d56f13e905ce811d53b0d17f095416e0b5d572bac7e0c748c3add3be7b137f15174e1b88c220df8234947c1eada9a3d98e84cd0dbaa00a14daf168a7d0780ca391d7f2d0ae1c2a05bd086e01ab4924dac925880c44207def2c3c2b61d6502a241fa68d0283fb6f74e7b0b9c63bc716246bc35a8cf4bf1a9316b7a2eca43f8dbd440a2fd04b3081c8b262fff73c6acec5b77fe028463bc51ca467ab5fd9bfed2e74c9cc65bdbf88c91f0b740645679216e5c2273356bef944508c6a02bb90e729d9252414804b91f6be53b632ccc34b174e2487b37d3d30467e9bcf37bf6c2d5d5ace32e6cf6a48a3553b7126b57cae4b7db58ceaa95768bfd97831fd5e562132e573dde7b354f484557fc63603c9ffef66347682c6f7f5aeef3a533b64845f1935acf9b302125932f964ff4483fc742c5c97c55cf707d5f19eecb7fa675a1317355ed6ca4cfefcbf2059a91d4c3b00369a49e5b3a946197262514ccb29abedc3d749e8587492702ea4d1997c145928ba6296fcbbf1f4866a437e38371a1d42b89a1c478fd0f564d927c607f5c62ad58531892b4b183d3bee97476b41b192f00b8c9a9de6b931fd3fbef3997d42a7dce4e4098c84b2e1a372a13343dc700e7ff65d2702fbec81f7d85bb9f0dd886a44d1149c771e488a3ff380a749ae428a5c865c8e43c89b4b09c7158fabfd68e35e5bba273282dc1ece6926246074873ee33489df95fa9b423ead12cab917c84fbfd85250a93a5514d4339f1fe5806461f21b501309b6ec0803aedb294d25ccc3eaceee913492ba49e968ea1d24189fe9d157f7e0ab6845a6522315f61103648d1552916695bb2cafa21b278e408ed8f199681fc703870aee1564a71d9f0f0096694bd928375e472a4639bbc8895d134dbf704d4a99f19c076ae4b41e4c58f7ec184dc67423c69df965069b54aa6d494f163aed219ed191f7f0829dd656f5dc37c94435acde6cdb045a278f5a1dd44866d61c708d5ab3acaa5389dc46d4ce5cc464ae51664d147288d8b6924bc6daf5734db87f627a76ada27896200b91be24cdd72bcd7c8df3d385ad459cc8f214cc8d7f84ac366e1bebcf51cf2b01ba7c0b0d23bbfc673c1d0495d1b0e1ce7f31b315aa2249c56a0f1184d34c712d548854931ac9ec1e47ac105ff680a126be2a7c619a6251c7b48d6eb46b5f3c962dd192cb308749bb0d68b4b6e3d5e9d5f2bb1cadad7281103bbce1083c6d0d0821b0721cac39ffbb8d923439b6c5afae4e6867a9daac0bb92f3ee32ce6a95a4aa1c4efecf197884500902b961b7e5e483108854c1d4bd7fd8dd92344909198cdbca8d15dc95c29ae5aebfec583ca0eb8a25d9e773d89fb14e61f421d94589bf64f361185bf506776fce418202256f65ded06a44ea721dcafdc90361ba6be836683729ee026072222b2ecbd04f6f610996bfa4edb16fd4a9e05cc2b47fef00927c8483013375608cb61573b5ade667a9ee121c9d24f458b3804f521e54e5b254b8d30083a0be2a785214dfd30d010020f4cf4e13790c4a2fc56c56239f1b82ec42f35d5067373e358418555ac2bc1ef691d58486470c4458201cb0668f5678d606db027bac4b68053a9580770609c531e1893cb850c86e44127fd8c20b5881531fe68364020b4a4e852fb0140d42be04c4564dfd802fd98bf6bebda52bc090e862dea036b7581560d524452adfa0254661af00f54f17aada8a772810931ae570577a4ec02572d80331e4957a27f7c5eafc6dacf0cae94ca45731179db1766c78fddf888ec189c8ba212869f2e117ec371dfccfad0b2351054e5b5729b3d9cb4f087ad6efba65ac9841d930828f9ca5322236b56c63bd7d6b930f84b56eb41110d45665f506beb16e932d03423c7b7137f767ea839809d9b2fab18b47f10da64ab6cb260950acc9359eea4571cedb6cacaea2eae5cf1afdf72bdcc567fe335d6d179ea248e0d677c21b9ba724786a2019e99db3633c46bd89a47062ce91dd9da410f5a7e82dd2c5e8161aded37cd8ff20c2be23e3b333b07fcc2774efc666317240f670c9b3a329cd6fd3c44fd9f93db23c3c89d35c34c4ace3dca7b9565127c77b25f7591cefa2a4d97e5751eebc34cb5c95b50deb58d5e5529d8e3d5cf666169a447df49a1335dabc8928a769b04a5b45f3fd19e037b015e386eef4aaa45835cdd86856f19005989d85f94c18de4377f90f9ef9fa5f7388c5c80399bf318573625c87fd8c8d9bb0b79c0cb3b8b89f861fe68ab79e3d9abcf5ac2ec4e1b86b692644daba9848d90f59c3b952b157e5a8fc6481ccbc4315f66a8d1bd9d7d10dd4b86902e1bdb1d555b2b51ab4f8c100af67cc05d66b74da783c24ba8ed41254cec36111d347eee8f8af25a7524d86abdd848b09cd2cda34f3ddbfa18d616be3e3c04573a976e044e63422c16d5323230230c59ea173049cdce849b1a2a1e66ac323c3b27bf1d5f83a1af525e66babe0db1e75ae9c86ee6b4d4dceefde991eacf94bf8d8a4ed67b463926ea7f3395ca7995c7cc8404fdf1186be58df6be9ceba505c141d5d02d29306c51c1d391dd617320390e90f03fed82c24436cde9414d935f4fc4172c034c739a1759c4cee4be3378aeed4a9aeef03e73c98726baee0f389966d1845f142b99f859187f07e5fb1ec3f5080d765f482ddaa7ee49dce310fb6313e28ac5b73b7e84c29f3c4fc0d04219cfd655f158997f4df10c8d9ec762c35169ee61ca0dc72a5dd15e3ebb8c08efeecdaf48e96004c971050421a7ed0d9830b812d9f7f8d1ac510f8cc4da745f5f078f95eadf067eba3760f45187f1aa8821e00252f4e6176b2eaf8b43f168d3c1cdf05f99cda9e3456b6ddd494f77209524b341b639a30308a56ee79b76ac662844c6125d5269aec4c01a31ea108b2f0d3d29007ccf9b19815a2915935d8a06a21481bd75156d289868e401498d2ade10226f48c69f2e0a98b4f54530a11b2cc7745d4809550a8e835ad47c652c2d3793230101a75eb060f47d4fa036c5f743c7cb792f5811a93577ee3999e393c71e53d85f999f36fa9885c6ed227a0558955b5e7a74bd70b3e8996ec2fd0ff3ce7db116414c0f80a33ce430865d4513ee31e8efbdce3f4cf6afc03fb60c7d2b149cc6ddfc6cf5726126d10d73e70f824739ed98e7c073c8e26a95877c03bf2e61e29db16ece5f7218d7f40ba36657d235f64aea9de1ecdd9d181ac3d2c38a2babd155bc59549e3a18d592291ac2841d904e0f425e41db58291ccc97f4c8945c43852f83f331fe2a38b3603a3219629a7ddba90682a88552821f6ce66653c51a563faca473403166814b5661e4f6a2ff0825483eed8bf003f9f488cd224eba03f1c0ee5692b060ebf7d5b766f9b975b2542da7a64b04db6a95c2658a36133bd2e500b82ae1b024bc18136c2c19ee86da687c06e8ffe602580a824ef0fd9b8bbe4086e40292b16f003bbff73167e8d81010cf8d2ec6b991038db17a3cc19ef6d3ee6dbc063c4d460a3426fbeab3534dbeb73983bfc9101f5687c5c68f52278e2ec49e23868bff0ef8c08934b288f6f7ad8afc5d1192ab5d55b87d4f9ef3c016e4d0489593441b03ddee2379b4cde666747be47b41829db2f120339bde4f19c0a9a73fcb114a5c341630781fcd39bf4af79f52124a43cfc8c374a6aafd4cadb4533a5b593e47082092a4af7a87fa2508c391aee0d839ba37ff0bba5ab93766a6e53987aeb8b8da93baed3157e2f1e40eba022d2c0fb5e85bba560f0745afced1cd6a98ed58df1f077c0039cd522abc541edbee20d44f79d37f72bd11ba3ed75449558d584dac4a7dad76e8e88638c15f2f4d577d34dff8eb317144e3b7fa7efa649435e3a00db57f6e753a2caa95a1437888df14f83e85c6761a57cf14f8f1a146e0ef883817d3d0d1b4e28c03a4bf37993c5297af2d46c279895bd53b467e45001fb8bf90894ae19748c5ef9fb480614681b48bfda0db1c66ae19ddd87d998efa81f1ac624f97e07c349f4a6b97b72dace72fbb78528273235f9016b25e0b135d0b4f141c5056f24fac6e33865d0e29802a68f9685d48b45f98585d65b967d0ff73ce655bd5f1a55bc0f4564ab855bcf197fbbda5d314a9764466f8442060f00dc16bbcc85c42138bdfc0005371fb8557f34e37cb7964d8c1f80f71ff7fb2988f48bbf95409a3ab9ba9688744fe0ae7adb996ad004e35debcbdd741d15a94c71baa2a2491b11ee29bd12da2ccb38d6f840e165fc103caa2f0f4fa5a38ba03a691c8b790d3f53d0635bfd6a9d17269a48fedad04776b610d8d8bf3e4040f44a0e8384fd46309d976c4b7f2bb5d223f556bc66a65e35d87795712e0c9420d8004d325803a728d0dafd597934eaa72a812065ab28c2f5be3b29bde52ad095231057ef49468bea6814dd8ace19c9ea95230399109eab7bfc80efada535fbd5f87e2ce01a4386b01227a55b5136aff7ad8ff0413536155c9162bcf48fbed9b04c4fe8434b69e3b698ac16477cff51324307f20fa3cb275b629478a96d639c40baf5614eca4f10878a48b0fe135b06fdc349ca4b1f65c8f536ade614d7a2c4d9bbfec410183559a9b7ded22f43364a22922c52012e3296866bea30dbd56a1d729b3a9763c9cfcf25a4a98e0be7df7878f959ff51afeae2c730c7c7a4034c98b99dc85e5ffee36d2c29240c5a8c295746667248b42545122d35fa5f91cddad160e16398a93fc3fcb47164ee2d261e409634c45322511aa753f1b9de7b549a468e47898da3998fb8fce2de36d05bf7ce020c8bc0b62c97c637bc33c00e07da675885944c9a584a508648c53fecf75c83ffafdd349bcbdeead818d6331ec70bfd4a84eab9388bddf3938014bac59f02b129c9ee7059c7e54f1c8d236e206b7fbdff4442f3b42779227a7cdc30fc6fa0356d7180a6f2e1a723b614529342529505f6cb194f4414e840d979f989805ac10211be297e7766f768527e7dd5f05e31affe3c10fc1e0cdd6e0804d1fce768dc41a83bfa893ac7ccaa10969539aa76bf4db2b38123d8b137c020b60a6398be7f0e76ef10929a351824231ba300400cc8b8b976c907f3807788d29b8fc5e813e5452ddbd60ca18478043a318bcc4cf34da2b7facdec621a329189abb42615dc1dc46fdde8e4340c9f06e3aec816be0cf6e8ba9e521b662ce62a16dbd6ba937560242c5eaec99f11c63e6364abac4038f393e00a64aa6b5d818fa36a3e09a016feea77af3687a11b04522f159664ecf6b0b5f4a7a1b865df1b794c366141e7bbb0bc68dfe72e15b8346d324bb81390f28329ed6436b9e28748d36eeb26cad627cc9e671d48c6150b9c1856e1836251b85b37141d3c8f4f62c9b7ad6fba38c5b2e281896cd904e207cf17581d544b849b5c8eeea5878cdab8f63a01164bed74b0f1f63e4000f57510f53bf8ef0c31f52284abb00fafec5b2d3414dd0cbe4670af479bbbeb399b7e5fc2a93da07b8e66ed29ce5af714f7da07cb85de05bb0a575f48733b3df6cc6242e70d6cc368af7be7cbcbd7a77098564d42301f893572156357ab15be2f494c9ba352e9b72bb6ba562e44edfc7709724e52a463f77a5625d50b2da467d0be3975dc893032a8677effb0532749b5916558d098b13b3fe3ee80838770ac039eeb01123b1515b190c3bafd101d75b4ddb1281d3498ef98d1021f7ff6a8ebc9c5d86a3c566bcd7becdb5db72680762648f8d407a6ca33d22fb028999fd704e441b33f523283930d495137c64f2ad37cbe4d325167be7806aafaed893688e63268cbd2acf619c9d03615aab3de4dd98a9efce1b9fa897c67706e4499662dd575eb7b0081cf9f9fa7a1637720dd0e22151da3ca7999c643cc9ce6d1acc1772f3354e5d236851864206a722fcbf67ba19b7621c8b682998bc28778569c75baaa8dc65ebe91a43e651904fd765f4e39ea46c8f0a6b39b118a12756af1357095b3c02e9a101c50f7f0a0eadc980b8fc6e72b42b5ef59ddac410de5ed4d3b4b647d29aaacddb15008a9955a25e069a422f44c47103cd8291dbf8081cf751e8bf5494ceb2361aa2d2207645d9d44c06f97473b8a2aaa1623dd07f4a58edff7ac5075f22cdf60c61b29c151f7eb7fa89baa3975e0d17d3cc49d0e021436a275c09ae7235299f1b7977cba30d1d2eadabdfa878431c4a9dea8b88b0786bbba3190f61ae2885340500e910f02594008d37cb479d6ec2bc22492f0ecbd86626f86a99bddf6d102a4e64f01341746c55c1ac2f552675053f517d3b32202260704dfe6050452a0a62419a14aa24b52494a9d78a1ff5815344a5901bc5ece608ef5bc2818a9ca022f513b63623fe8d05caf9a15b4ec9dbb048986edf9166b9e5afa62b75ca7a9cc5b55081320b364a81c2150a110b938c08e9560b55d8e6aedd3005e28417c8eb761c862121b72df58b409e941f38e5e393cf9400c2eb4764078fc7aaa21e4d3b683017cc97a24753668563859a37c834b753dd4cd6310d87e80d6302bad2934d92e82bee6522d5b03ce84976ebaa54be00865cf47d2472cb02c4318979e3f369bc0ad3829e27cfd1bf9cc5f81a6e65e32ded1ead60fc98769ce708d8854768762c82c0d8bbb96487660ca795cb266c862e9dc14530dcdb72c01e6c9409bdfc0d69d93e0e21da1cc2b63532cc5c9b79b0dd328f9b7ef006c24d1d4af728fc49ca8e53849a3f942c21176882cd8147a0d8b3d2e729426a0b47cea867cb2e71f9f50597c5c7efa7687c1634363938ad501bb0fdc0f81178de65f00634ae8d1222dbd6004d97a65a570ce996070a5d905961eda444f4ab82824be806e4b124c5bf2e7b44fba75276d4e8d2b29e62888948006f7265a0502492a9d80e30ac9f42faa5db2f535e87114e8dcda1a9011e5e9e23e626a8934944e6ce5dc5ad5c67d807928cd49f30dfd63965577f92ae128cd827c6893fd8d748b2d0affdae08bf9dc356e05ace7e99a035b8201cbfe4f079c2f543948f463c62ae8921fe75fdda43f6e03ffee25246522f7a86cde9e35f84fcdff0564b0a9c50d85ec5c7800719f731790ec158c72e72afcd398e1bd2664cffd11fbbd5c129214c2940e5867dd6edd2f646b0712837c4168f35e329bce7a8ea5aa0499f208e82d71e39083977f6c3708966aae38774282b9da2789c6dd92929e436a8aab1836738dfcab615b049ef1867a8600a068ddd66723b460d4fab48debfb58d7642379ae5ec28927dfb2d1fd0aeaedf752a03cd36ae13913ae79dd950df9d3ba66095d0ec3aac298bfa8ae0351b765a3462fab4170240588adea83fd3bd5577260a3ec8fe18b6dd0fd0224b32b5f6ef5c77604ba8d291311c9cd7d74570f5b4e5636113739afd66c184a40c2c488043e5066d9eb550e6fdee675ae84de47813811f95ea4fd11ec5d99febd59c578fce539d0102d28a0fffe606ef3e5ab1ffeef05fbc60611e2ee85c50f83e8ec68ef973476ce3e17055f2bc1262b8a62a667e6792298f984af7852f6dbce2711d40bb3bb79e2a5431f13c8c24ae528a0facb04daf6145ccb0c8b29d4ac274407fb5c3968a23ae9cbd796854c3f7a9b7a2cddc05508437f22b8a31f619624802d933a290777a2f25c93868d550efa6b49e69a156582c8a16f788b73759fbd4ebcf0924bc5840693746d024c8eee3b507dada157f5413bfa621c6537a44fc98454ef2eb5625f40634c76335c96c65c486ee9e10f67bad23971ea3a6f75e4b5f7b5a1e55420d70bcee41067f543f0b095206ec7f08bdd7cae49fd5a3807cf4fbcf3dba5f1b739cc24d5d5b1d1fe73d2f3130d7ea57f0ec0507cb1387aa066ec58db682f875503a9ce42ed62b7bc908d7d9548144fd3cd69edc4373d7061e16fe9ec23c4682d8c6c1a1f46b13814dd5da181716c169724efb4a8a27ec57466368cb27dec468ae36d3d08888d45c2c1102a79d613959a927906cdf3f741c5286c61db6ae4f36d13d232384c9b707a136a228cfba49f881326e451d0a23f409be1ac675c946309ae38edbd49c8dfaec42a3c0ee60e2c56650bcf44145e263476c3657e61a3b04460ba0515b088c64ac7c0f1202c56f5725ca50b0a9ad966323d826410a38d229652f94b4c697ae03cc4213f7e3b9abb0b2663c3a5dc1e038d068a491bd7fbc48adbe43889697adaf9e3759df2f4a4ee36b2c2f9607a58c8846ec5e475fc5ca873ad0aaad1b3c0576e88cd8de45873c2520e1b39cc85254a1cfe1d0e5d891353475bc0fb08fb21b9a4b0f93a503b4b027e3cd108b75be8ee58632e8dd6c6abf8198478688de11a8f8cf55e2b49083ed4c2fdf11719ca5b1692ecdd82360f41bd20c6caa5eef856b7be619a2eec50dfad10d2c822d312e3765f6533523679a08e8c3827d0c537a98840a35a4eca0d6e798644281196101dd0d9fd534838ee1ee91bb71e3f9d2aba6e9bd45b4c6a5f8f1e50f245f29db100fe9aec383f0b0e6344aa194b16a91121611d18bbc32798a2ecffa5f3a94d682c70c172eb2f5d3e633c54e0c38e55d57895facafe3ed32389e0feb11578ffa49654dd8ffff6b428a70ac1c6232af2cc8649bd984c6dde81357f7b73d8c1edc393a9d95ebde26249a169652f6b27477fbd741b49b8e81c36dacca56544c92db625d882aa6d934e4cf9d91a90eb4817b30363f679fa1e49d95f914bbde4d23f6340dfc949d54c2bd6dc686463322baf0f3feee79d02ed74844b58d928e8b403147e1327aef630ec91885a310bdedfee6a7ab8a91de6ba7524b9e635c7eeb55603b5d593d5a81ca97e1344ecebf6f0f323be73665110e9cb20dbd01832273f6c63cbc929bb2827e07d262d8b092d3ff56fd1eb9a8a6f52c584680a68365f36abd5e048c9a4a91e1974db45d6850571da2daf3c31966bd588e180e68e29715fab067ac332d3446cf01e6341adeaa1c7fc72a587bbf016cdd59740923c2556eff2d6b2116bc94df8565d06f3caeae71acf24f155b74b037eb08956b50e510b68470f802f3252eed8c73262653667597933694e39b08d876ba0715b6ef3c1938b7077528ca97cdee6ed7321fc36f2719d4426c33868702bea7c65551407a4c5ee47f5fe442d1726129624568f1596b6e5e87870d216711599cb4f0779633f991080d4a8558b2212b6331eedaabedd7005334fff5ee95d16f4a43252e022338bc5a3c4ca8fd4a7583e9a3f1575a911f5a7ba49b66c130828628377fa4b615dac540ffda7d09e13f7957d3daf2b02526059eec68d3652010002b3ce64c1bfacd6f8021332981005ae1a5ee34ba76886a7706240b9a9420e2af55fce3ae0bfa6450df67bfa13dcf5fd1f25b8e8287fa0334e009298558f9d5341f2ce9638f9ab9a1579df2c0c99210a7ff03442038bb404ed5ce1dce8d8f02c2a9764bce89f84894df92d5ae843a86b85a37b6d14cd1e5be6f5c4e59c090330ffc8ec25635190353b182263f8a3a5ab31db6d890255f92bf39dbff1d8fdc204c1daa9ad5ae27a8c87ec7bb50fddc1aa5342a9b24ffc416bba21df47d4ba612b04437cadc91dcfa20931a6c19920dcf0aca7638d02459ef9291cd635ee725342962f6980faa7891034b64f26fda71a3ef982e39dd26acb15c5e3e6a85603aa19b8b275f7e2eb6d79654d7129ba7f08033cba9017cf43f0283ce7b98461128789d8c64f02978acf777aeeebedf7aef9c2450e126010ff98f0f55cbd7d678e23c232c3086e361a3e159c36bfdbaff3db30b3f51fd6664ac00e96cab4c686648e41c719dfe6dac4d2e95bb955fe6e595aef868e43cfd79a996c165dd9ff98997b4e94b1caa015d51cbffc18052939e0d74293a616083404fb085f59e36330507adb65b04407420f619bd0949b5abf2ecb6e6ea24006602f4cfa0fc48551b13ce45d64311453afe7777b8e60d024856ad404ed8de4a5958d2d2dee3b256ea01464b080fbb268eb1c5aaa07ee2c57c21e9598cc8fce7917fff495fccb5fd6a3edbe7a61c79a0ab06b84fb0decb84ef70a84d2dae9e703cacae5cd8d32f960484e4c715e0d5728be4d8997ffa2c9f49de847363fc2ca6b79e26578d788af4465072f439b236ac01ebbcaf3243ce3bc8dab28f9bb9907e8e4dafc26fbba466502842291d12ff809bebfbb6cfb713ee2a170c137a4f978c80c2d190ffeaf0d869b9fd4ae9f99403c29ebcb737e4cddfefd6a5b651fc66d05cdf1b2ce7e3a0e4c2c590259168af47cec58979f1d9c76e480c2800e63c90d97f1b56e4ab8a71f4c702b7c2819ecab6667aef24ab4a7e3ab270e232ca6e1190046d9032c1cd02f2307627033cc45576c9d683a0232caba0009a5c96d873c5f1b20ed30f2a94c8f4ba77562950a31ec8e0d9013b3348a5926de72ac79c7b5baa71ca71999b9bc41fd36d6c8cf0500b119d7cb5f9a54359bfd6bb1c8d18937224d609b600151c7a302fdb0ed146df798cb426b8624fc500dcbd89bc376edced41fb889d375b5bf8d5433377ddf8d1ae4d7738e482f9d08a8579b4496be7a4167ca2e5e970a4eb46c6549f7ceefd26a1af3d4a3d88cb1785a52057f81f7bc1eae87128e57b444619c054c7658847832dc552b75eed04b6b59a6459bb5624f35fb33178ba41690030608b27dc783df7f856bd9c89a8d0890f15c15e89d6f6082e2e3578bd525acbf7a48cf0e9daf7f8b4ec38f2a195a93028201d1371e5d46b439669141f1a4d69d1a790058275df0afb4e9dcd570ad60533f690f453f50d428b9dbf406e783cdd219033891b269ebbdd5f42396386e13e4420abcf66a9cb6d9aade85a49961f604566901bdc63128ace362b6b90478637de59f434b20b95b25440436d7ef8f6a778623ff9dbb022463779bbe4b7a6f5675ba256ab810a5b8a854b3c06b18351588fba850f9efba8640e1c3b15684a2f53527f37a9315a9b01ddaa861858802f9390be74a1d1791b0d7eae99d3990d6f8c960139d0a3e7e05fabc3a2270ee76955aeb873f4312f3b01f4ac87571d07d48f1be803304634cfdbcc29754ece48b3a30c344f738a23e3a6f50eec4725e8af7f759929581163adeb0912a49bbb2bb73408b58ac5a2c62cc64ff87ab95a031dc5e55e313d9d394a1ea06bd7d8e5ce581202bb15bd2e007128ba1dc2810679ec98e8e2e5d4efb01330d8435510d9d4aa65bd0e1dc2ffc5ec964405db10b4f3ccf1b71451a5c2712771ccb3942d0ec2bc41a8cb683d6f6c6d2ae38886d6ca2ca6cc20c6734ff91e48da35049e567a5309472a2ea6cb5e03e473c28fc2eed5cc7da8f2f3d13e695543df11caefb474f953424df2c01249719d1b507e176ac205f67f5cd7e7421e00914968a3332498c6d136ff985465e364313d672187cd6174233ba2d35bf530a5ce761b148c760afc49eeb6a3562ff307d998482d4e7948750590d235aaf554a4a86ec2937ff4aa659a0376171a07e979ea25d11e838585b6cac52a306cb61c4bdb7f84f68f12635d5822b822facdecf4ccb3ef0095f86be7898448fb71e52b098b693a99ae2a9ee974de338c052a88d7075a54bf0aa942441bcc305fb75404a5f21363038f374fbe0e6e9ad7b7cef4b864c6cd7212813ad60b0f914dfee7be4b359158807b3ebf4c2e577ab61a4cbf99bf6b25f7c866d2523e69ba12701bfdbcf6d98c6e95191e0f664f507a38e5e09885d2a5569b911fc42d66aa84740ec547ceac05199f63f6f7eb8998f7122710c60ad3089aadca6b3b33487539361b6598265577314fb400866e53b4ef2eddd12f465503c31dfe5ca3f593573267d7a9313d8a113df53b44b610703bdf233bb2ce39bca6a75e1e359880f5500ae73400227d62f5d8a2ac81a585c307ecc8f01f390cfb1cc0364cf7354e84c0b22ea6dfcd160df1dbbff243b3615e891b356d49eb8a082bf2767a3524aa618f86040dc1f3c6eddaa0af4bcd00d73b7856f9c48a632c725679c49df5e26fb06db10ddf723829f826feb654f17d1ad670398fdff7848333e694a327e34d07a7b610ec6fab60d1f384dc08b89ff8db5aab089547a55847ad8e8ab6dacdb582b44d9d85bce751c30929c70b5de52999c37782a9a2120b84b7697f68a327366bd09b62a0f4d8eb7117fcd04ef1a45ce96dd9d921f36211cf742d454709cd7fe4b286db6cd974154935d3d6e91ef914c8c3cf1af7a395a83f42edb808957291b4d18775a8670b1242ff9310f360162ab95a9a14daf18e7005c36a15b21ae95a732c4c22578190fe3a029c9080e0ae6a0bb69cb585474ada5bed3a8239eb4cbc941cad41a0a1602d0b072193f529a90aba1e2ba03532f4f6e8c19c70211d88c178461a2da7e7358c6d892da89a214aebc7f4fed4b81d145228abb57d54f72804d03922fce2d48b2855176722e835f2389d52bdebc2cc4b164bbb383f08115b5dc299899237c10158f4518cea622a61b2ccf7681e65ee2d6b8d7dfbef4713bbb787b1ac29f5e6967612f6a304a66877bd5b9a73ed4398cb1c7d3e76e6b9321d1199ef853d7a9bfa38a3b7bb3c877f84e0c826deb808876a36ccd434d4181edc37d79f92f45037f9e9212b0ca2408a1072857bceae3438c29654305bf0c3fd2c5f406c60378a96bf339e34b182bcbbb7b0d99a090680115a0112233566a43692eedf4c653662f6808a4fe2cd48d79b0fd70ce2d2718fe3bd12737a4eea0bda66cafa9f1bb56323eda9baa117e1f6660b0a1be328f5cebad6c59ea0de6fd819c493b212b94c04cb87eac5e75a70328dbf37a7dbff40e09804fe2b396faf1820bac42a54631809b4f4970f6285b8e2f128aa3d84d2e27ead1940d2092555ea9fec39c187aa1329ee6abdab310a4448ca746e606dfae559dde925f28898cfa606fad956f66b1073063072c47e716d754dc5615c2e2f60822542b6b7348cd58d2bfa8fd4f2a1851a3bb03c40ae8d033bc35b19c78ed6353fcb2e1eb7007de3e6f46d501d2836d98d71b87f1a0010301549030e3a4ac7ec82f8878d1377ad10f7fcc37d06a35a502438368cd7a90edbcb3c62428b5c063e30896fcf595688c7c928a349e3ba411f82f223f1b5cc04ab5b595d8c65561b54fe1ff9279594ac8f7f429133c1d485fdbb92bf418d042f5137f18d73a0cb3f92ec502f0ab0202356c18f32056ad75d6273ec626c5a9b306436b807ecc8614dd0ccdf7a1ecc911a869b43ebc02083a138c828c484fc5bec58d87d26509f6a769e1db248d176c1dc70aed67b89a891cf0cd76936a89d2799c3fff5268cccdb55251eeeb31c70e8be88c157f60f2e3f0de7662c1369e8b321edced3816f0e8cbb1cf20b3c1a310a985e71669c5cd25b147e5bd7bb37ac14be26afa2b2748a9961995bd968cf1a506bb9e480a634fb3922868d30de36ac128e5b87f7318c790347de7280a5a68f61415b146decc78e56c8b64c4df7c0a15cf943155eba33f8679659bda2ec7becfa0626dc216fbc2b4cae5bbf3004f483dbf3b6a00a55a31029c020343cc4c101229710e28bbc8f5097b036a448204aad93273ab56da65cab301494ba0aa10c5e955b49ee81d3f37d764c0f0996668f49ea43b704bbc1f3c88d92aa09639c3626327995c0bbeebfa92e63e22cc986a04f81102d61543d47f2714e39071c402174fb0a107017b4fc7661f1ad309eb83800b1dc8cee43cc8049d7c4d398cfc23d800166ba417dbe5f633431240500fcda76dfa532405706ad73858c9d7d9e05f8b4349ae694d675b0d9c1cb1064f75a294599da0043fe0823db5e85902851576e07dbde7d17bc97840af5aa756c0fc87ec09dcca4f5a52740aea442b18f3ae5ff65f39fc51ebaca144fe602f7f9ef15a883e402aae3bce8726330a4b48bcb8a7768a433b47a6a751e576e35070e135d7a6af36a221be4c555ce1f1ab22cbdbb234c6845639eb82aab79837d9b7421d42aa7836ea08769ccb5d172152d6c192ab1d55f42ac7f77f23d0bce5cbf5ff9c5673de85fdc4229ff2b99eb5cf0105e96074e26a2db17688e32b34dce2565c164f89f455c621044b0e7b4e1dbff6be1a0d490d5c56c9479681ca1022b61cc1bbc695b957ce903e544cf55ed5532cc5ad81f57a0ef431417a9d79dd3e961f4477163fb3b2f81211757b0206bd9e46615bd9149352b2ec9732cbb4588783d200e11428aaa132f583ece5745a77cc84acb089a3531fae8f631e10ea4a171472e65989c21e6ac33bb95e79a541a72379c47bca3cba53515774b5882e6c40cd71d88b11fba628bf8ceac9b4b20d7be0ee08b4634dd19b3b99afdca516ae61ad2ac2be3aaebce6c6a45d77ce99e80beeb2aaa6d4d72e39854b5682af829727496f30d5d7504053f14a2d9a8fe1400034770ae77e327604da27785090f8d827b64d14da7daaffa43abbd831e4762ba1215086c631258be3ccb94b159c9716c13813a2f573c9f1ae558212a39287ed80ad3b2892bb6b49df2bdc45660b0e3217dd185cbb6d8a64be8227a0e5b0bd12371d1a35da390322c0e6ba92c430ea24dfc3e40c5c81296779c4c15bc71eedf8581358b84c4daa01a86433864e76703e53a375caede14bb6c7bb1b23df15e1f6b6fc62055923526f2f4621f638fe179277e1dff1eaefc31fe7d00c92539d67fd496fccc620bba5cfe37bd07284dac906fe232c6881fde79254ce4e868eada75e2b33f25ff993781e20c0f34fc26c6fc997310d2bf70dc474b3273d4c82f1bf596815a9fdfbe7bd0ba8475df2aeddbc0ebaca0454d1b5d7e54c36577206efa42b20d2ce27c011261db3ac80910ea8e685771d64b8eb66f5db50cc38dc77c38f215f307bb7f55bf4d1ce651b16196101a45ddb3fd550ec9669af94f5cb93b16cf7b1ea2188bee1cf81f28c588978f2323d1fc115f95ebf4bd2ae8163c1dbdea01e0ff5fe2d496d9e6cd18e67fa459fdf508db209a3d649d6a9e74e48c28ddd216a3245815db038a80093f2f4186835f5ab184d56d442d91661f657401002f737a5401a4213a8655339c495648ae79420f1280f49fee3697c78d555c264b9fc4f0b39ff1937878533936ccc9469071cbb16aac683a2bd50b89ca87906665f3c53d8067caf235a42baf2afad4e1d9e2084b82a14d5ab457b31476ab9125e5c746ebd61bf1a81b3579c02e67cd6a2d23e5898bc678dbd331ddb57d148ee4e24224dd22b8b4b3222253c386429b8b80ba207e85ab6a2b838a6452caf35466d2a9bffe537ef0701c8bf5f0ca9b48b1c9727b3b4a720a04588899a9f43d978e51ba2cb6c911754fe88366c18490e065baa52cd9ca68ac379bfca74684fc2c3797ce5e22322fa9f0008ea4e6531f0367e7c6d6a652c6aa796d19dc06365eb04d85e1be30457f591bb1fd5f444aad8ef298d62daef94f7844ee8415e951acf1258cca2b662259c7eb6721164a60cfe7061084407e282580511b4b0f9859187475d20fc6321355bae3d26f6f57cc8221b0ad73e03c41017112429b0e76743ac06c71494f7942ed652ccfa50fff92845aa7d7a505cc49d486a592f1792966beff0583c66890c33082d395c078aaefaf434c02938b776019b4d5d6b024f5ac03981c271454e5a0b815bcd3cc136bccf7e9686e57ea620370e4a3b014897293a12392ee8833917d622d4c0338004c62a764917b092d4a86f25c817d249a69a7c32e0b290b7052b1baf575365020dc3d0c073a819963c619af1cfe5ff0aef382e1727c8708f5ddf639977c9c647f9bb91289cdeaf81a26e0700770fffa532c87bf5692ad25da7e978718c1201c4db5a3c451294c6d1e3d1d3bb9936d6f6110dfe8e3d3779c61b85c1cc48c2d0e24017610b33a12101c66a258d515ec5311a7104f1f73e801dcb357d56048fc0e21a782f0c2c799fcc23c984100e593336479fc1b9f6a668c27421294d2f887645b4d9da50800dd74f367f385ace7536a683a81218e6dc6c4c4b7ff1d4400a80a59419fe0db1b698fed25255a46a3ad6bb12004d2b8d95af83c3a14691968cc09c723abf0bc2c8aab0d78bebbb6375a958773b611abf13b4b3c16243358939c8512fed2419a47247abd4b3e0d2970f1af7c735fe42a5678cb2bb46f3a1d79e4489f541b9e270b93277c9f72549e4121ae1d0fdc0f06194a1a71ba8c5a3db8db1d7a916d67b3e1ade8b2b536b73320db9677d77a2ecf05e17cf1e1584bcbec1f2b5bc70b9ae2e4616f2ebddd2398a8f9296aec1f029f9455e97a619d19bc49d1fd34fca606635ccb3ec70cf34ab1cc0cefebbb0363697cc19244a18774c9296b1075481cf0082e26d39cd2260f3b651a895732ff01d94523d9d1a9bb74f97df9d9eaea48da141a895c6799b6d78e5ac64b941e0814a1afe5cbfba32355086b09160011329b27c7dda9279d35927e70501c8f7b3f7765b1c27ff8ac6731909f92a9df137979c9db309b81f2e003f28116b5650a949401e0c1683fb3d0757eb0b4f0549c727773efcbd5041541732368f4a89dc3630f118c5830f3e0db827b5453d03e6d0132901325185dd82d3093577e83324fe5cbd947f555fc5cf0a85506e639a84e35c95b6b0f7ae4f2f76ee6f599cb1f39a78ec449daa534ce0e2c417099e7809552bf762011ded8c7633cb8d6ff0651f5216ca3105366a054379284dede27f67dbb0fc25ad49c4ad064716c1c4a3aef8d806e26f8b0e86c2c0bfbea26616befe325f6522bf95113ee6a24b1de4735fb5ef81db5c9cfac9d44b532f602c62e0197b3bf38bee5735072319a447c86c351d006bcc2192cf87cf818f5f7bf64503cad3ee8a1dfb21eed61269303799859e64897e3ce12b17e1cc677abe6119dc5143a44e7ef39141a05bc09688b6920ce895666aa1c16811b82d50450b58a0d5d14362f705110c24c8f714863a997d78e5b8f0aa7f65cbb02604d42027f538e355bbe60aaa161717dfea33869c60e1c3be7ecebf8eb6820d449b862e1f46939faad245c9dccac8f7ddb5a8b4ad1acdff623bfa5bb6b14077a36c7b0344163ec376c743843305c43b7aae1c599ce3b62764990ade4756cc982cb3b91f6a5de17207538624323f32bb1520c756bb2ef32f679eeb7d4e2a3b13bb91f75a51ae94be8f8d0d15c5805571b6ac3c62f79ca12980f770f87daf7569d1dba034056cd7a83d89eada8e8aa13d86d0cd58bd6a0c29c328d22e11aa24235c10a2a83d4b37aa1e989185e6c193207e491171dc12d2537ebdeed08f96146d2cce1951bc3d901767a352d99f54484df305bef58eb3c619cd31b94fcccc026c0aefa627ef542f7513d841b7bb091cf1d01860fbf80494198b5d9512b4c017da4aed284c8c3df28976cfd96d441ea851802aa55fd008e7cfba2612e36fbdd45ac0cb996e97622d86085149a62691eeb5d5806edb16e6cc248dea802f68f42bebb15fd049e731b27535df374d52c5c40daefcbaceeba3b54482f6c23bfbeefa05328cd5dbb79c43ff2b5d0cbbf27bf5f56095c5afcac361aa8034e5da1a2cd907b01e9baa6f2da91c3616007be1b79bddf22072851f88efc852bed0dd51ff344add39c65770331a5e10e36876b74ae5ffb8d3911c5be345d9886f7cf1968244c9acfb09bdfb721554e4ba565562d4fc588395635330a36af2690bc3b1c4aded173be0c902c13c9c09f747dd653ef048083b3405ab90c4473bd69529d07a74c7f32083af9f57282a64c606ab8de248292b8430261c02669c8fe4230143d00922442adbbad963d1b4e7a2aecc4954de46b1d27a565d5aa8035f681f397d237354d01fbc7974d3e97cb4bb42c28dd743a6d9a022aa38f268413d9c373052c71872babc6f5b63abbf9b70d17e24266d484f6c1c607a68f79d669a82494241b571dc3b54e54d2d3bafee4c4e93cf8082dc57ce50ea07acae76c50641f210a85e26a0be05c887dd40754fab9b30d17f19532156a2bd073e99ec0c5af5d0435bc894906108fd49482a64314363f537a3c9d8831a677723a607be1ea8a22621a596effbf910089245d233be8e6873d2298ddce666dc11b74cc5977b81b3402d595c808feedbf3082a96a58334cdf469e40d6e8fc0378e64d4c737828fc4dfc8981b79b987313b35531835b28555c02a47e65b8a036382b13d9e6c9aa10b8894b36bebda3534a0a53c0587878857830013d27b5f72ec4f76733370e03e76677b25e3cb0b8d54cf6c2c98e06a7b466d9e1ffcb4a58acae6ac57c0e4439cf007f3c1a81cf52d28ceb46c493f0c633d042e3c236848d548415eae45c3a666e5eb1e441d655b737cea67907cae2e6057074d63abb7c33358f896b454eb91698e61d3a7d4930d4af459bc57742acea535e3168dbc681ee6326594431ea2b48a45acc7fec325dc4e4898359737f2239cd1d5aaf36b7741005b1f41a41d1ac2dc11cdcdf12112078451e5432d64605e0f686219b656dc8cac1e591b5af8826a71f49fdb4d7631e3d66a09427887131e33ea8a9d10a0a555b492247a009c2a05e6a9187ced7f650696bdfe6db9075185880e43bda5e9303197e122221f7a027d5bb2ec200aa905a2110e6f12f0911b910a5f16bb25370d43059a2ee8507ae11332395772afffd83b197b213d3f3359ff43211dcd71251d17a7b21f1bbd0e0b0945124f7c4ef488f91fe1678cad3055ccd8ab09b23dbb78a5a5258759f68e96c097b4010d618fb02c62cdd30141fe6a49f1046786596e3330fdcbcddac19769d1c6f2a426c060819ea3aa9f8f4a2bcc15b4d1d54072c940da5d05b017dcf2f0f5adec154113bb60179b099f674efb176bff8b93eb519c1178d84a87817fdb8f3def75eb56e3ba8cba72e692f2df0e7004989b5e3e6f3bf89a6d587b517d2dcd4b778eeeed41f9038662e1044e9f59bb8c368c288c52873cb64e57d1a551402659e27bc040ffa738b5e460ab395bda477bd88b53b4f588c59ae0c8baeeb433725891402dc479fbc1c93bb2310c4895fa520d3bc5b33d1415447b98be4416bacefed524f32bbc85ac8470b08ea6e3287806eace3de9c179835ed3897ab9cdcd851f81ec107eee7651d3393839927766875a383e09589cb7df7c1f814dbc0ef4b6b80a538fe0244f2c49bf2919c74c0456942970d7092021a542ce9ba3711bcd5e4b5fe5e6b5db62efc5a0d9c7cdbd44fbbe20443633ec8b59ea809bdc37daef0a3d0f7cc17fcc1eebea2e83ab6f6efe97386a1ee7f56b647502591c9fe1558036158ed94a4801d827281a64c2a1eec632c5e979767eb5388809324c8f3e58ada8fe9848698a8dda95a1de1445f34061e3396537b774107fe5e2ea1a599a5ed27707ad4afd10ee9044f437eb823d6848160ba08edd1b8b9fb378c43e111877e743a52350a77d429c30e5873a753a17d4760e73f2c6589d2b69f23d5c3cd3f72f36c169bdec36d380025c1f28e358c96f4bdcbca44e4b5353c64a3e3961f7119dc066f38750b8331528a42f20cd36aef4563a9dd42846020dec637e43a390dde33ad66f6ed15b79d03b99c68b11e18937f514420d4da98edd9a55e65db7300c3449a0cda4bf9e5dae15d3092292376d860421cdf29f0b9c184972f9482f14f1a990ed5f24b1e6c9b02bca2a9032aae5c3dbe08322ac5d1b864ba2e8d1c5783bfc286bf8019991ec4999634695f32351045c29db7310818437e2cce7b4851bd8857211254b222d8d14bc4483d521c83f9457bb52feeda8b37d265b174a090285a0608f4cebcc59c898848cd3748cb5c6cfe61700abe684a4514203198a2865d76d4df97cd3c5d6fb3ef7aa0719025410d79665d35bdf8528b3a53392cc83430aa7a4cd9b6a02d71565b3fbc9793780a979733c9a7f3a95bd7e4c8d481fc9baf52324f839b777a626fe0b247a639d3f608de89be5046599936a49e7a02d742c80919e87eb1ccdcb81410b52df8062fd4c57cb359e8f2dc7118aacf90ccb69735a2a0117479208b58e49c8cc70074e761937bef2186d1255004e81b84f647e621b56f1e2d00761a2689aad9a90b308d321cafbaab7d8bf6842459eb9b466d28694bdce3913a22a655ebf4f6d5d098bd22b77ac97addea323e3fb1a85e95a9f7c6f4ddcb5818bb949961d51c4c48458c694ed14d69414c841e89634924bcc5fb99d6ef59e1709fc5442c0d42040ceaf58d25670897e6793ffdda2b6903cf8277e6cc36869e8145fd3b02e59542c62c7eeb3bbca01d8ceeb2e384b51f0e8495a6f29cff937284c5696d926efbd442577abf0a02946e94d27f9920826868a1854c483adefd9b7eadb016c26d3686ae4baf3a85cac6158087f0d5e098e91f7f542f395bc41bdbd5d4d71bf29d2012812b4da3639d50027d3c001b221f400a1e6cd143a259a71f5c7576323fa7c4ab09759514c2987b4301c61a1512f5530e118c6cf2d202f8647e24880b1ccbc1cfdbae70b96b5cc99c189838094cbc4703a73541d136b2bbcc93543cdbca32e94f40e1831b8bf63108e2c0cbc8a7915abf46bbe0332a0483305f50b04a9d8716edf44530766c30eccadb3e224c22317489aa26d65fa0ead8ef913bfb790d01fe84bfb3061f5404251be3890eaa9acbec3e651ff13095a80faec1d11d143136939455d61b703c96247f9eda47c3cc9ceff1244ac7cc735f56621197660020a94c1eeec7c94b569bebf59d6541d0adca68e199b8d175d05132b09207e8d15517ae3b23f9a523afd395b281dd59af715245b97177ed830a15fe243d8d755d2e9f5f420430d26f1132e6e5d4845ed04fa23f9a5872f7615bdd92f9468d89625b74b4fee967fce51723cde788e0245d7f449c0d199ee9f54ed2b660107ff7436328c44ab5fac14770fc1dad8608707dec3ae91772b1a99350fb0f0188b934f2f9fc6a023f23a998a8ed31ebc53ca38919de1ab6f7ccaa58b119a02696c7f625de8f62fca41aaa98d653cce8b2a2420a73a058b004134fb76ea02ee8c2dc0363999a411c5a666c3d7edb38d5f53466d9c94d1bef40b5cdbc96947a2e2daafb6847aa69444aa1e6c9f2341e8c7fae25c4f1a181be2fb0a55d573e7df90dc8fc610b06ceac4d5f0de6756ef322467f2d0744840d70e8a343d23375bca01a121d6a6056e83772c3622ecd68934c0075031d69eaa99bd938e06e409d0218349e12ad0cfdd1bf7a93e97a2375a0bd41b76925d74d67e54b040240c728fc11f4a95702c3e54176b7479f29d6194caa02c56a4653a08cdd0224fc067a4d0b7a20a9525da0b72a489e5425e986ad1e4357485c1b142e9179254e0b360b91b4f90ebe0363b9a85612f0b67921d8dac1b38abe8a086592cb77e7ab71b7700c5028941806cbe59bfd6ea6e5c67454d546e2c13c11ef78ac5caeac1c926b6fd4593f5d02de2292b264b2588121900c0d7c0471368a60729021dbc423216740cdf7926e954f041a48c543ce78c5e94cf59a42965bd45252f9cb648cd3681f5ff1d12f666a8acd2f8cb4f226f8be403a985d6d632f03a22ba8c7f334f567c481ca732aa3d0eae125a6492af0c30b23a6d3a8c823f945dc58408ba731263435a737b43dcb411bf07a7f5d222652fa5d700887a450c66e1c79d985f6b477284c47fd8b22336bfa84d676b375dbfcc62e8e165e070ff92ee184ea4dcc9112362eebf9ab6ccb6ad5dd0651de8ad0e9e02c11db79a06b4258661d0dfffba2a91f36c83e7a44acd506da1419304f29be11546165f0f8994d532c1f24a8936c61cad0bcb7d1728328dd837b34e6daf4ecf89cb227efee7619bb6057e2f612f608a2d5fcfc4f6be039fa71ba6ebb9730ed413a6abeafbc1e7c797579827f9090eda029be5f90abc53d8624a014374877100fdd22a21966b5a1052110eb0c91e991932ef555f6dd6d9576516ad9b08c21965302998dd9588d592b4826bf717bbb4fe08d13faa5e9ba15ef6ed29cd203a7a1db465b30eb061658c5c9105bb644c9b5a4532ec2c80857bffa9fe7d9568fd621e9f8349f8cc34ce05f9709a1315cba883760cc999aef7341ce90fe5ec750282c6ee9af44a1de54aa064649761f871b9482ce5de185938d283f596b07316445d166477584e35f7e2b528b6ee636b8ff1cd18a287869436b1fa2a241fecfb2c36f6cb500f456e6c2bb444857bc1cb770954d2f5b4b91c30ebd456cb6a463f87de1577f260fabc64affb4117befcd75502d80d4f506627609eb67033a818406b02f2b93108d45c83fa312265051ab1baf17fd549cbdaf8811b60ebbfe78125183c3bffb1e2dbce6508bb7dc3b5ffee6037de8f4fba80efc4fa43118e14049c3829cd25e9cec4470d53a6a544001f8e691675b61817fc6835e17b6c9ecae938601fcf37cbc308be430bc2ebc1a153f6915e658edfa8f13e4a2bbeadad648d900a534c078c5452f7f88650316c10608430aaf3ecb76f76b390cd332c9936c69adb203f816758b31996b116fd388f2ad8de7302082ee2271f884088074af7417c72d388781e9604ac5ae4c54942b2727a4a4130f0f9dc3b8016b91f2e34d22840d52a9b87ea9c77569b8036dce96df628daaa11d6cfe3f449d073471b9edfcc69c9af428f5f7724a21aab06adf6cc976248766f8e78984b0218c3642f756ed0dce4f837636504ea80c92c5800c39c7651aa50de1fa8e53c0f57ae41b21c201e989be1539451f7a7fa7d4375bc6e9f1ffb7ae5e7f0647509cde8b2f5d42eeeea080d3e9258b9741b800ae0570f7cdc77854ead0417e8f4e3e991261f369fe4e0a69d293fbaf16eabb7ff805c79631bea55268441cb9ad0e59f6ea39b9204e8023ef74e73542e3c325cd4c1a453c9059961b7e07c6d51f761a4c4783569f8f5ef185d00851de0fb3aebb1e115f5d45e5e17cdbd9915cb517559829f0ae1d8c2f2799055f76809e90a5e1115aabd9043317481673760cbf12d5ae05fa9678353ef0b13f04f79a277d2210b652394446aa2f76e58fa169838f8ce1dab501a0974d43c7633ab2184b96df7f3a405664b92d6f7c8bebc1bd96bd54fa200fcb16140f2ea7bf440aa35fbedc2117b981301d946c8de3318de13b307ec6504e6da026e8d1d9e42d468a1fc08796b167f0f5cdef47cf5ed34d8a4ecf4a59b84e3e9dc948279fc8fd3e9ef72cb9c24a7ffca3330854641eeeaed7111cac80251b493bc175972afdee4993b90e35154b373c76e1805573c695dae8cef6f25caf1caa5638c989afc13f95c49c8c00626069d78a974242617dc14c240354724b92fc42f4a54727eccf8de13018fb0d3caadcf25a9aeb55bc3cc43ba230a5925a6dcbf2c2cf33fd79cb7e31c0f53a6484e17ee58587efb36fdd709c51a670bbd919b1cc0bdc2141c7bcd6a36c9a74e62b7435cc910c891acbddf3e37219bb1b0c8fb1dbf0d75f5c217f96ce909bb0335adc6acf82b6c64a18f4df356655512fcaee9f6aa53691dacc8276b4103f670651fa95cc957aef2a038995967d4efc159ed8951ecc9f4ee1a7398de28440b8f7b85a045259b51ac8748a68a6654bf06ce30d44bde427c27a3c1ebe230736442f12f8d9ee8591bbac42173198d1d3ee6f2a3688078c4e0c324dce98916a7781aec2e32c827550800be9939b08239752df2e21743e216cdef65c9999decbb7950e8a66cfe1a227f293e0253fec6084681b6eb59678aa7ca06fbc2f7c539c144ac4a164b0c0fa1bb29133699ae7a6c3d5e69f39d98e7489d71a47e5d005fde803a7c0b1e9663b16e754674f19b13fb202ecb96d8c74f4f72bc88f4d495eba1a812fdd9d972a23b8dcd684c8dcfb162ad5520f4a2bf7aedd31e878eb0811033e40630e38ce0da6b980035f0941fdb110fdb16ab8456474350d8aa77fe6b2a4de5824016b27e6760ae24bf4641d149b28c1fa7c0224a052f0bae305402b37682eb18dd037444f2bb47a1ac3c95734722186b04a9ea60df794ee2d9c91d1eafa0787d68329002ceae1e9080a6c8453940a33ce2f44199f33efed62ff1ed08ddf03a3b966affa86bc2709e092402f87fa2c29ce731c5a3b38c9a880c283d20fd7581a5ca2bb6decca45335129c1ce46a1a74b4bc7e6ed1d278dcda0dca5e0eb200786da99851f41db7c93bf4dcc7bd6232729c52d530923b58153bb92ddd0e5e907238ac7631d91c2b2bc9951c9775a1835c4abf3c0bf6c814ab86832a42e2370c79a99c83752abedf3e426980fdc8e2246e77224970cbe82da9374a005258967b80ed619c08c8a33efb58aaee07badbf3c31d5d4962a8bc4572042304658aafb99d79e1ab6d417e7fe3739b589b82f03ee86ac77de25365ff5f63b15df43bd5bf61d42ebde43f74db9407cc05afebd3aeb003c0884d71d1b59e32405c3e3532e8a01535b80c937e0a3227b020eb3103ccb99871687efd3f1e68c81a65cdd5024f500a0dcbe9e13a02f48f0a3b7932e009510e309f6f5156c9a69908d9695786e6cc550a08ddb6578fa2038605369894708265e3a31127da7de3b0913bc8114b152abc08248f54d0dee14cbc1ceb39b255824524f2e4594421ab76e772ec134aa2c1c5706130d73b591bc305b6936b221d072cf30e3fe4f04b8acd1ec73ab39ef6ad45bb5ff1a7d24b0fb21046275fa21ab078c593637894a9c78d010235bffba6dc9a17f6b0cbff0b6f1b020c13af66bdaea0db552fa259afce2f506544a48a209ffeb82fb0cba4cec1e61d11b175758208e8d94ea6aefc4a7e0e1b920c8e94f93d5304fb629d3c160e3c980cd2adadecf2090774237e4258dfd30286abf13a54a8242e490bd00f2bdeeb4583470295347e0929afcbc1718f42e2574b678dac34d7faa978579a9cc4619a116315cc5205f76a9aa5b0afeb1394e9c82cb52ee9b69fe26e95a53a4ff10c1144995a84b7790ce9313e0e28f8d54062c7d43d9ad5c94c2213333b562b505096e13242f258301bb1b8d61b56591e56676f299bcd82e40c9bac96ed739d176254b00d1044c2e2b7b037c40f449555b6018019106542f46bff59297b2dde77b8d5c73918821c4164ce178a566ad7ccb134f768738f773ab2462c680f04a41ee896042f4e1b7562f6cbd44f32c188eb9d03cc1ebed72b8c7778c2b0c5e06b6cbda6f7e13f2e56d2b530ad7696c74579f599c3cca6847b4c5f5f62749e88be9a4844005222ebb35c41b4444e5bc75e0afcdc0f5fbde74203258327efe69ca8e7b061739a6f535f6722f55f56b332cc80f21317dbfc84a54e1410f45ccf5b52272e649a0d6f4b0e6e7ca0bc6608597c2b78eb1badd2c90cbe5444e787985508df029bca2a0ec7b17398f25fa165aa9f7263e9afe0588db3937877df0874a88662414a412cbd888acd523fa06eccff878d74d95e0196aaf23543b5eaa2a33bb3236c296bda39ebfb66871a6466370f5a11e5e37fbfb21a4967534c62b8cbb22e6c3824ad7055d50f059ed4dbb26bc214bc08a4c26862648fb7a53a3d2117bac88bd4d72b005827f6ac3e327b55aeb3919d498200dffc23fd50bd0b22938cee4a9b349beebac2f8841f2b1f5d71035cb72b95909dfe639cc29536be540f5d58308a440f1ebacc0b4d602a1bf47799d2d5e4e558b091bd8a9d46aff966a9f391ce94a835709578c055e28915d3c75734554773ec8d18de80b95a494dbc516877034e469351f2992f5f5d7ff3356f8a37683d5a08809ea2470e9d9f1c521b73442e9dc149ceeb180af622bca4f238d5c721a97a796338ca0a7f2d944b65712b5034ab179046cb0c4657337744a855b5cf25562905670fe62f1759b3133469d40bb6200c6afdcb061fd99d19384754c6fdf7c43dc90767b04512757e9444543876e592793d1bcbe4d18766155889bd93ccb54f15c2158bbe53e7f13af0da1a1585c6c14fb206e1a84441bc8643a9352c99072bdcbafacf412b75be17ee855b9e305ab1b39909853e6d978d18bc4b353af449046cb7a590935f5b8d9f886c84c356f03950740ced06ce013f8467aa080071a0f64df7779954767de871cf3a1a7b1a5223cea441fba47b3e5d56abb76a760128a2bb5a2519f002f78a8a9993a805d15616d9d210f066b4d6aa8206adee3d11cd0bb7e798fd31a142d6c1f6830ebe2e09f408e39e82641499c0ddff6bb18fd5445b7639c79a3ac795f86783dbf16c6d8417ae1cf827381213bfc4b3594bc169d0ff3a5655f267a1c03d7bbd90310b523dfcf8aeec7d4590e10ccbf6e7dc31e620ac49404f6f6e3368c8534b8451da4701f25916f7b49faee64800acef30cc4403f0940e69059b3fbff8a5bfb83c6bf5a7fc8d990e844acb2eca53a37b11f21ab06c046fc3aa4c440c3e85d124e93876140f1946f92b183cc35135eedd258799e57b882aae5edd23065f49bc36e1d532d838eb9ef1e505b7520a1e55e5e00df184dd0315ac10a63c36d9522c26eb2e0e034338ebbcbc260ddbafddd560296924792145aac64aabfa7e903a89960cff61d9cfd57875560d33ef4fa9171d06ac2da7043e76cc76dbaf8d3ec892bd752cbf9166ef0e66abd197b716ec4343e0b9e04b8f0cb89f62eb78852e1ae560be4d546e6bfced4a44f88fe1a0ec0f6149b4d2a27aeb9e937bf4e625ed31869c55dd30d669b3a828d9d65636a06145bd7126d1a162d3c33131c7f451a805968c029c3b4075c81f625345d8b50e15c36120527bfb73a3c750ad7944426bff4c6b995e61ecfc949ac60dde3fa4221bc8f92410e9b56c6efdd8d5ad5985c961340da06d11bbad95bb8849209a9318a6971cdb6b9453339252d4bf236e9bbdcd8fba8deca14a70ad208dee292f9363ff87512a8297a0e4fd89c7fcd71688e21d34440b74b371ab9b652fc450ef3f56ae1589905bceabfdabfa26bb10ae67adfa40582faa0b4d2d3b6c6eda6401101edfe65475c64dc6adca62941e3c2f2357b161ea21db14ffd5e91b4e4404f1eee030e35b1acf7f5d64df68fb0d5e374eeaab5d3d805a28db260f12eab2904eafffa64b0bb64ee0ce1637ea88b6eb133ef42d4dc2be0c97f6dd5593852054239affd051a7d1c8105977b055515c2fb93190cea99bb2fe7a1748cd3d72461ac716add2c9636d6486f3c30f44c0cf1361242507b506029899e457b7696f1abed0dd2c7bf09dc3ae600cf4e1122d522102bf0269453287e1f94ac20003a558c2dd9ffb02c9f390d51bbba79d99b3870d980ad860f8a91cf4e47849d6f05099fbd146d89c6743b7eece8264d44addb8ea2d9bbaa5e2138106a5cd60b7be881ee8d8013cf7d69b9bd06fbdc32ccac0dc11f9d81732f9901f28dd054a0d4ec480dca59ba2b2c41fbe5143c01be6f31677d910622d4f61e45a003e0c3b76076d6cfc6dd8299a84299954f9563637663339361b430e73b17056e3931f7af21d1b6ec00d2480c7f05acd704507996524df00169c64839bc933808c989ce63437e0963e07156950c84c27989deda85188bcc20aa4c1915773682a02f34db296b59d5bc05195e0a9a613262e2cb8de7893e2aa78aacb5dd7416efdfbb99fc7f177dbf6ff820ec76d959df1439f5d5334806c8673fb6fe91b5c3b250e7be637646f39ff7cd3b929cd6dbc6419986d85efe3b4c4f195077f591e8869b65bcc3aafd1a3bc92b635e7a902de1976fb50d963fbf13d200623cb047e6c620dd42d7a1dc51b9738f82a7638569597ced91651ef8fd152b922933037bb62001222f7bf5cb2b7e663bc1dd233b1c16560b14c58fb2cbf0a4ec723fd007504a5f46165d1a3e2668ed59a6f3df92e43d761adc49ae94f58207b73db16436a58d5ad4233c9522e6c38bd27a3cc4118a973be7cf437042617108e207d37251ae5c9ecda7433714cc1e8b4e98834c83f7ed499b6088c25eaa68d034195f28ed88305d92b51b2a4b52c7480286031ff3567634e407be916a9bcd41c1f3847cd968b068a6adac36a26a340f0cbf6f1bb96eca1f2f2d6e5756471d03047ee1e0045ee62b7904895e2269c6ea2eff675c801f1628d5c198a83088e5fbcc76b13acdd5c8abd5b236ef7b444351d505a9275d5a65cebf4ed93f2491645bdd43780cff6a27fd88704502f7f3175678834a44d2728731e58c1a597a0e27fd65224f1cf4b2ec2f4f42ac180ae824dbb99b7116ef13d37ec94822985a58712ad46efac5be18170ab92818fb238caa84b7e84d0fa9d13b070e45a7736a82c130c8f4b3eeaa933335972c6a12f7e3745833a1481157855265fcfef4becd5b2e89ccc0b593238b3d4618dec9c11d3c95b7fafa7f6e7ed81272f6ad564cca96407030646f7692781d4b1637f7c543a6c93be03cca390891cc040199da98b9d4361e5bf560ce82c1591eb79be06bd2133c2db55256822a8fc77a0741b7b1ee55284b58fea3b9b74bcc2aac56e672c34de5b6c82659741a80300b9b67d95afdd0c4e2cfe9248066a0f06ce6af569ecc40dc0f8277e954596f89274e96e2628f655b533e56784e5dc35ff3cc137f3069d32ee8ca3c31a3f8763d376fd08dadcfeb6c8fac1b4d55c3146318cb46ae4c0cc7d144f1237009ed4b50af20b520fd920554655f1d8f64a06b1d8037f81f949e4e7404275ad9ee02ecd07b0004119c57e02b44b67e14343747aedbcb2b16c7f8c474f8fcef641b4b74060d9b7644623bb1273b72cf367a45df23ab05ee93708800ec8ddb6a4c02d97011431ed7721eb5bb18e7375e5c67b948ad0b6b9876cb19005fa6104f5cdb768f54843263dc18a263a1f994ab8eccb62bfa1b4b80492427017a67fdd5d6f2abdaf8dd4ed7e93a2c8b52e0e4362869aa5c1458b225ec6b7010629c401f0fc026f1d1c97576b345a424d02b936720476dacbbec03c58ae28f0fc0ed3467358129b139f83fa76caa928ac13593a3780d89cd5e7a9f5dcfb51968ac54f6775b26e520759bf58c153ed274ee92feddbe319b676e73b4cb749dc907b3fa9f3847b18eaf43b89f48543d2edb0ea220c344e0feeb563d49ab10d98ff72a0444a32d89d23f2a1c81c4c8c4b901842880cf5928ce076f6dfa6eb813ce70b1c3d679dcffd437cffa8e0291b849f71264b8d7ae3af8069e397369bb81deb2e97aa4549300bf6d15e446c1ffd05db964cf4a28405cca7a87b327de2ff9c9d4f619b46b1b01405f90849ee2eb5fa71835c1bc8397ea10d40e5472b927947d57e029ce179d8c335e932a28250c089a1acf137066ceda8844e8258623930929b5b09e1cfdb780157e686a4024e3b05f3f01e0bafbcb140989fa32c7893015e929e7ea51ef5444ac8ddde759b992f540a9b596743b3092d45b83f6a7bb134cccca7d9d45491d5bce124e79d01614d3d3899eae4392d9e53aaf9f93a86dcf237c1755d85fbc1a7b8524015c1e56c712726182b3790db2253ed4a8548c19853bb246cba7ae3f687c00d20d506235dbf752a9d0599984ec12d2c11febfebfe010bfeee4f446f4c102d0ff7078f4a64b25a3937057f73e6ab6bfda63b6c1ec9b1b3bcbf16ad7fa8f12abec9ac97a71c0bac5b412291b976bcf5a55fc20267278513b0f8eb33560314eb55dffa5a55d3be60024acbe23c30cfd6af06fe5f5383afb3a0bc4eecdc108d2013dd6be82c03177e48796dbd854fed2c373e3487bdaf5fbd929d5ba1aafea4e00544d64889735449fc5aa1b991feb2dd0827ac78b329836dc1446db20bf5aba4779c1d4458433ae8d0fd757dd08aded24a69cbc1d71e102cd7f2579300beef203ef24d2a26e4d55e51cd1161892181eef0938f5fd9d0d2e341b66f1e4c66b457ea2977db44dacc117f239054b6bff4a55af9c638b5bf76bcc1dd1d184d9b42149bc8cfd09ea5bf4a928239ca9b7c845518e9f6fe727a2836d7ffa1bfc0289d9cc1f25351168c7d0e8e145c3e433b34f65e3d3fd2ecea1ce5373e3660046e3d8f1dd84e9b306acb04b0a1f624be5350c1fbce7a9b46f25dd4f2f1c28f820b3b3e47b501f15e8dd4950f7c431aabea0cc667b47f0ec00491f7929b849c644cd767b5c9cfbf2653ddb3db4224a0d6952755a6b3559e6c3dff1b7559f9a7e1fc1dea6d173d36fc644a8da9a5e870487e5c228c1ed644b4a98b847a58ba404bff1811196f76725a12a70ad12708e3906cd2d43191288f1a5bbdbac35b3ec6b17fc311a084f573f50e2eb8bfbc002d4f18ac2a517cecb8c2d435134801647f02575e2e762f598b0d846e07b9b0dcfaf986bc1ebd405e27de68bc291dea7886adc585e5c3ebb28524ac7fa48436bdc0dc34d4548d1bc046b295cb97ef41013f632f9c0bd7029f35850565f540dedb466cf485072819a47f71dc30cd92a9f5736b2eda63e17f42d268645dd9d4d853f7745730996bcd84a91c9d23414d38667ce6ce38964059e8912d0135ecef75bac6cf3af9ccc557c08a2caf6b5a740389a2244dbfc004a942b421fc492f7d650f2bdebdd0cf8e584006961caa7eb6b4ac26b2ff9023a1484b711c42b450aff039ac9313689a32f80bba44599dc4dccd77121bf638bc972c372c7e83a77c06b9db0daf85d1edc9689bf6d26a85532df0a4c906157df3cc78a80da10037fc6c3f4044d4c190019e6cc0d557347e8c586bb865fe85f0a7b00cc71e6f34bcdd3fbc7ee732ab81f0c6d077f7c0ff9efdba92301a3bee54b940250c17837d952a9010bee40ab4a191e1efcda34538c96fe342205dca70a75da6fb31abd4a5e23efcf9ea937db743167bf8c16651fa4351cca796f33d3c634becd9371d71890c72081493ae49fd144be8f0a0b48792716db46d4f8021a3939cfcf105b0869442396c8299bf68e87624fe7cfa111638c30c0bd0003c6a9eb8acfb7f7529bddab1757cd575a157e9592429f9f9b6d5f2e345d6b15d7b14b4f2225af560263b15b8dabe952c7898a973350e6e074bf0a8fa3c2ca6e40105ed2a79f9fd043ab5adaec5a70034f7e2c36ee7b914ed896ef7df16027333bb797dd7d4590b9d8cc0d3163c90a8326f65eb41d74c8a2a7467e71b40d2e4878659a04c53abcf3bbdbe20cde9ca27ab4cd9b899d3b725bda5bb36f6285c3b25c197bb770b26cce31b9acafae2095aa5d38b5e767679bdfbc34c9c08e81902c370da38b3e6514d57ee47402a483d6b6efac62dcd753beb6e5e44c041e36098589e3cc7770ee4c68f88d68dc7ea2fd0594efeaa4a3cac812187373bdb19f8de8297fc9011585296a546c3145e801e4c40415c287df85421d36b87a4fc3b6e7951016ac817ee2eeb95870d1f29bcb193fbb11029a5402e0eab93b9ece8816904982cd2f7ecc65be26fe395da52946f9a353898643f6b503fb663b4463b3eee3dde70d9e99a1768c37e5db38ae67be8dbe5f1c75fa0a4a80a2df81f6e009d9eb757503495c7e5d5b62df9246305a2e644421e8884736b11cbb5bb089ab8f91c14beb74ec5d9e05f344cf7242bbcbece2a3fc10d3adcab1d15544c1adbb45cdeb1e742d91065fd71f5dad5709376ceed66880c643436def96a65608a7d38fa21a2c0b80e81af69d0d9ac22352a2fa971a378dd8441d696a62715361e12fec335271cfaaf081aa8813b247aafa9f46f0fe7d184a280828aa9b5d74077c5550f1ecab777122f3b6d412b0607b66bf3b4993a8419cf3afa4fe1d4edbf5b6a09386701bdf5b7c47bad6686c7ee6de53c02733abc85a50174746fc934a0b48811bad03c86ecc519bf4aad1df720d3cbd87233bfe9f5b82a4487b9556f615f4d718ba4b629b839855bcc7298fa93961b88d3a02aa7d04805f6b2f83cf9df28ac605113bbc3309ad90ab5f8650b770f59a1cb16a014a966a41769e8ae3cb4fca06baf11b1c9b70534f1031a4439573fee3a9c4b859691aff88697faaadbaf3f038bf4a3157b2033cb8ddd5732d53946d6a1446599fd115e7718fc4c79ccef0fa2e59993467edbc0d451972459229573357044664d696e282621a073aeda909c236324c95289a7c4efdb07b9b4cbe6d98441efc632123ef5e9574082efd8be9c106ba5a0f6cefece5a0530557b26adb32ef2f4a8874e0c09e6fc224d2ba9e8173220b5f6f0a30a0db247504da4b0e9d507c0cc03214652d04599931751b4fc6da6744672b395865fab7c6dc0e0d40c5a58c2201d637f8d200df4c463c445677d2dd64ea463f014450098605fb1e69608b9849ed88893fcb91a11bbce511aa5fbfb8b273b68402cf9f910d6a453726630066ddb54eb9d3ce2bf1326729df27277edfecde35a49b650f803a8d86ab4c470851f80c94e83e95064d84ab04f4fbdf62502492fcf91ae15bc8513823a07ad81fb22b3f1483b920c701629b3a371cbade4ac1453ce2e89bfb1f67d14a31e8c40e63823e35c17ceecabb3511f50310e3d6a20531047b08039b21aa9150ca5ec8137e9479fd753441b710c67744403ac23e360475a94579a7d4cf13c4d93c43100d977bd3006de63dda1b0336fc1bd56aae7d3bdfa208cadd78e568dba498b2a62d483d048e27c435a3624c52c7c43f696bdf7bc5537ad33037bc473cc8cd0594fd7de8f07350fb5a68b847a335e51f4f8c675c4496c08447be6f683ec1dd48f2634664d3620c305b399bda83db6b0d008590a57cef434e255829d64d644e7b3d0cba79cdf61a6f98d3287402e0248d942c47286b72cd794a79f6f1c84d52f1e0f647a89ec6d4e3c3d26506a1154ecbbc93ae1405906ce2a8ff67d9d24b9e43be45946cd0415235c74be915ae90fa2f2ccaaf246fc7547e47e92f4c44d02fc1a9052f589f4c963132675c5f086d4e84cab1d910727e46ae","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"779b78f0b0e284ba3ac14be43b73028c"};

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
