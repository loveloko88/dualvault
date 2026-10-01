"use strict";


/*
    ==========================================================
    DUALVAULT
    Local encrypted PWA vault
    ==========================================================
*/


/* ==========================================================
   CONFIG
   ========================================================== */

const DB_NAME = "DualVaultDB";
const DB_VERSION = 1;

const VAULT_A = "A";
const VAULT_B = "B";

const PBKDF2_ITERATIONS = 150000;


/* ==========================================================
   STATE
   ========================================================== */

let currentVault = VAULT_A;

let currentKey = null;

let cameraStream = null;

let currentLocation = null;

let currentItems = [];


/* ==========================================================
   DOM
   ========================================================== */

const $ = id => document.getElementById(id);

const lockScreen = $("lockScreen");
const vaultScreen = $("vaultScreen");

const setupBlock = $("setupBlock");
const unlockBlock = $("unlockBlock");

const setupPinA = $("setupPinA");
const setupPinB = $("setupPinB");

const unlockPin = $("unlockPin");

const lockMessage = $("lockMessage");

const selectA = $("selectA");
const selectB = $("selectB");

const unlockButton = $("unlockButton");
const createVaults = $("createVaults");

const biometricButton = $("biometricButton");

const vaultTitle = $("vaultTitle");

const fileInput = $("fileInput");

const cameraScreen = $("cameraScreen");
const cameraPreview = $("cameraPreview");

const gpsText = $("gpsText");
const gpsIndicator = $("gpsIndicator");

const previewModal = $("previewModal");
const previewImage = $("previewImage");
const previewVideo = $("previewVideo");
const previewInfo = $("previewInfo");

const itemsGrid = $("itemsGrid");
const vaultEmpty = $("vaultEmpty");

const toast = $("toast");


/* ==========================================================
   UTILITY
   ========================================================== */

function randomBytes(length) {

    const data = new Uint8Array(length);

    crypto.getRandomValues(data);

    return data;
}


function bytesToBase64(bytes) {

    let binary = "";

    const chunk = 0x8000;

    for (let i = 0; i < bytes.length; i += chunk) {

        binary += String.fromCharCode(
            ...bytes.subarray(i, i + chunk)
        );
    }

    return btoa(binary);
}


function base64ToBytes(base64) {

    const binary = atob(base64);

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {

        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}


function concatBytes(a, b) {

    const result = new Uint8Array(
        a.length + b.length
    );

    result.set(a, 0);
    result.set(b, a.length);

    return result;
}


function showToast(message) {

    toast.textContent = message;

    toast.classList.remove("hidden");

    clearTimeout(showToast.timer);

    showToast.timer = setTimeout(() => {

        toast.classList.add("hidden");

    }, 2500);
}


/* ==========================================================
   INDEXED DB
   ========================================================== */

function openDB() {

    return new Promise((resolve, reject) => {

        const request = indexedDB.open(
            DB_NAME,
            DB_VERSION
        );

        request.onupgradeneeded = event => {

            const db = event.target.result;

            if (!db.objectStoreNames.contains("settings")) {

                db.createObjectStore(
                    "settings",
                    { keyPath: "key" }
                );
            }

            if (!db.objectStoreNames.contains("items")) {

                db.createObjectStore(
                    "items",
                    { keyPath: "id" }
                );
            }
        };

        request.onsuccess = () => {

            resolve(request.result);
        };

        request.onerror = () => {

            reject(request.error);
        };
    });
}


async function dbPut(storeName, value) {

    const db = await openDB();

    return new Promise((resolve, reject) => {

        const tx = db.transaction(
            storeName,
            "readwrite"
        );

        tx.objectStore(storeName).put(value);

        tx.oncomplete = () => {

            db.close();

            resolve();
        };

        tx.onerror = () => {

            db.close();

            reject(tx.error);
        };
    });
}


async function dbGet(storeName, key) {

    const db = await openDB();

    return new Promise((resolve, reject) => {

        const tx = db.transaction(
            storeName,
            "readonly"
        );

        const request =
            tx.objectStore(storeName).get(key);

        request.onsuccess = () => {

            const result = request.result;

            db.close();

            resolve(result);
        };

        request.onerror = () => {

            db.close();

            reject(request.error);
        };
    });
}


async function dbDelete(storeName, key) {

    const db = await openDB();

    return new Promise((resolve, reject) => {

        const tx = db.transaction(
            storeName,
            "readwrite"
        );

        tx.objectStore(storeName).delete(key);

        tx.oncomplete = () => {

            db.close();

            resolve();
        };

        tx.onerror = () => {

            db.close();

            reject(tx.error);
        };
    });
}


async function dbGetAll(storeName) {

    const db = await openDB();

    return new Promise((resolve, reject) => {

        const tx = db.transaction(
            storeName,
            "readonly"
        );

        const request =
            tx.objectStore(storeName).getAll();

        request.onsuccess = () => {

            const result = request.result;

            db.close();

            resolve(result);
        };

        request.onerror = () => {

            db.close();

            reject(request.error);
        };
    });
}


/* ==========================================================
   CRYPTO
   ========================================================== */


/*
    PIN -> PBKDF2 -> AES key
*/

async function deriveKeyFromPIN(pin, salt) {

    const encoder =
        new TextEncoder();

    const passwordKey =
        await crypto.subtle.importKey(
            "raw",
            encoder.encode(pin),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        [
            "encrypt",
            "decrypt"
        ]
    );
}


/*
    Encrypt arbitrary data.
*/

async function encryptData(data, key) {

    const iv = randomBytes(12);

    const encrypted =
        await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            key,
            data
        );

    return {
        iv: bytesToBase64(iv),
        data: bytesToBase64(
            new Uint8Array(encrypted)
        )
    };
}


/*
    Decrypt arbitrary data.
*/

async function decryptData(record, key) {

    const iv =
        base64ToBytes(record.iv);

    const encrypted =
        base64ToBytes(record.data);

    return crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv
        },
        key,
        encrypted
    );
}


/*
    Encrypt JSON.
*/

async function encryptJSON(object, key) {

    const json =
        JSON.stringify(object);

    const bytes =
        new TextEncoder().encode(json);

    return encryptData(bytes, key);
}


/*
    Decrypt JSON.
*/

async function decryptJSON(record, key) {

    const data =
        await decryptData(record, key);

    const json =
        new TextDecoder().decode(data);

    return JSON.parse(json);
}


/* ==========================================================
   VAULT CONFIGURATION
   ========================================================== */

async function getVaultConfig(vault) {

    return dbGet(
        "settings",
        `vault-${vault}`
    );
}


async function setupVault(vault, pin) {

    const salt =
        randomBytes(16);

    const key =
        await deriveKeyFromPIN(
            pin,
            salt
        );

    /*
        We don't store the PIN.

        Instead, the PIN-derived AES key encrypts
        a random vault key.

        The random vault key is then used for files.
    */

    const vaultKeyBytes =
        randomBytes(32);

    const vaultKey =
        await crypto.subtle.importKey(
            "raw",
            vaultKeyBytes,
            {
                name: "AES-GCM"
            },
            false,
            [
                "encrypt",
                "decrypt"
            ]
        );


    const encryptedVaultKey =
        await encryptData(
            vaultKeyBytes,
            key
        );


    const verifier =
        await encryptData(
            new TextEncoder().encode(
                "DUALVAULT_VERIFIER"
            ),
            key
        );


    await dbPut(
        "settings",
        {
            key: `vault-${vault}`,
            salt: bytesToBase64(salt),
            encryptedVaultKey,
            verifier,
            createdAt: Date.now()
        }
    );

    return vaultKey;
}


/* ==========================================================
   UNLOCK
   ========================================================== */

async function unlockVault(vault, pin) {

    const config =
        await getVaultConfig(vault);

    if (!config) {

        throw new Error(
            "Пространство ещё не создано."
        );
    }


    const salt =
        base64ToBytes(config.salt);


    const pinKey =
        await deriveKeyFromPIN(
            pin,
            salt
        );


    /*
        If the PIN is wrong, decrypting the verifier
        will fail because AES-GCM authentication fails.
    */

    try {

        const verifier =
            await decryptData(
                config.verifier,
                pinKey
            );

        const text =
            new TextDecoder()
                .decode(verifier);

        if (text !== "DUALVAULT_VERIFIER") {

            throw new Error(
                "Wrong PIN"
            );
        }


        const vaultKeyBytes =
            await decryptData(
                config.encryptedVaultKey,
                pinKey
            );


        currentKey =
            await crypto.subtle.importKey(
                "raw",
                vaultKeyBytes,
                {
                    name: "AES-GCM"
                },
                false,
                [
                    "encrypt",
                    "decrypt"
                ]
            );


        currentVault = vault;

        await showVault();

    } catch {

        throw new Error(
            "Неверный PIN."
        );
    }
}


/* ==========================================================
   SETUP
   ========================================================== */

async function isConfigured() {

    const a =
        await getVaultConfig(VAULT_A);

    const b =
        await getVaultConfig(VAULT_B);

    return !!a && !!b;
}


async function initialize() {

    if (await isConfigured()) {

        setupBlock.classList.add(
            "hidden"
        );

        unlockBlock.classList.remove(
            "hidden"
        );

    } else {

        setupBlock.classList.remove(
            "hidden"
        );

        unlockBlock.classList.add(
            "hidden"
        );
    }
}


/* ==========================================================
   CREATE BOTH VAULTS
   ========================================================== */

createVaults.addEventListener(
    "click",
    async () => {

        const pinA =
            setupPinA.value.trim();

        const pinB =
            setupPinB.value.trim();


        if (pinA.length < 4 ||
            pinB.length < 4) {

            lockMessage.textContent =
                "PIN должен содержать минимум 4 символа.";

            return;
        }


        if (pinA === pinB) {

            lockMessage.textContent =
                "PIN двух пространств должны отличаться.";

            return;
        }


        try {

            createVaults.disabled = true;

            await setupVault(
                VAULT_A,
                pinA
            );

            await setupVault(
                VAULT_B,
                pinB
            );


            setupPinA.value = "";
            setupPinB.value = "";

            lockMessage.textContent = "";

            showToast(
                "Пространства созданы."
            );

            await initialize();

        } catch (error) {

            console.error(error);

            lockMessage.textContent =
                "Не удалось создать хранилища.";

        } finally {

            createVaults.disabled = false;
        }
    }
);


/* ==========================================================
   SELECT VAULT
   ========================================================== */

selectA.addEventListener(
    "click",
    () => {

        currentVault = VAULT_A;

        selectA.classList.add(
            "active"
        );

        selectB.classList.remove(
            "active"
        );

        updateBiometricButton();
    }
);


selectB.addEventListener(
    "click",
    () => {

        currentVault = VAULT_B;

        selectB.classList.add(
            "active"
        );

        selectA.classList.remove(
            "active"
        );

        updateBiometricButton();
    }
);


/* ==========================================================
   UNLOCK BUTTON
   ========================================================== */

unlockButton.addEventListener(
    "click",
    async () => {

        const pin =
            unlockPin.value.trim();

        if (!pin) {

            lockMessage.textContent =
                "Введи PIN.";

            return;
        }


        try {

            unlockButton.disabled = true;

            await unlockVault(
                currentVault,
                pin
            );

            unlockPin.value = "";

            lockMessage.textContent = "";

        } catch (error) {

            lockMessage.textContent =
                error.message;

            unlockPin.value = "";

        } finally {

            unlockButton.disabled = false;
        }
    }
);


/* ==========================================================
   VAULT UI
   ========================================================== */

async function showVault() {

    lockScreen.classList.add(
        "hidden"
    );

    vaultScreen.classList.remove(
        "hidden"
    );


    vaultTitle.textContent =
        currentVault === VAULT_A
            ? "Пространство 1"
            : "Пространство 2";


    await loadItems();
}


function lockVault() {

    currentKey = null;

    currentItems = [];

    itemsGrid.innerHTML = "";

    vaultScreen.classList.add(
        "hidden"
    );

    lockScreen.classList.remove(
        "hidden"
    );

    updateBiometricButton();
}


$("lockButton").addEventListener(
    "click",
    () => {

        lockVault();
    }
);


/* ==========================================================
   ITEMS
   ========================================================== */

async function saveItem(item) {

    await dbPut(
        "items",
        item
    );
}


async function loadItems() {

    const all =
        await dbGetAll("items");


    currentItems = [];


    for (const item of all) {

        if (item.vault !== currentVault) {

            continue;
        }

        currentItems.push(item);
    }


    currentItems.sort(
        (a, b) =>
            b.createdAt - a.createdAt
    );


    renderItems();
}


/* ==========================================================
   FILE IMPORT
   ========================================================== */

$("fileButton").addEventListener(
    "click",
    () => {

        fileInput.click();
    }
);


fileInput.addEventListener(
    "change",
    async event => {

        const files =
            Array.from(
                event.target.files || []
            );


        for (const file of files) {

            await encryptAndStoreFile(
                file,
                null
            );
        }


        fileInput.value = "";

        await loadItems();
    }
);


/* ==========================================================
   ENCRYPT FILE
   ========================================================== */

async function encryptAndStoreFile(
    file,
    location
) {

    if (!currentKey) {

        return;
    }


    try {

        const buffer =
            await file.arrayBuffer();


        const encrypted =
            await encryptData(
                buffer,
                currentKey
            );


        const id =
            crypto.randomUUID();


        const item = {

            id,

            vault: currentVault,

            name: file.name,

            type:
                file.type ||
                "application/octet-stream",

            size: file.size,

            createdAt: Date.now(),

            encrypted,

            location: location || null
        };


        await saveItem(item);

        showToast(
            "Файл зашифрован."
        );

    } catch (error) {

        console.error(error);

        showToast(
            "Ошибка шифрования."
        );
    }
}


/* ==========================================================
   RENDER ITEMS
   ========================================================== */

function renderItems() {

    itemsGrid.innerHTML = "";


    if (currentItems.length === 0) {

        vaultEmpty.classList.remove(
            "hidden"
        );

        return;
    }


    vaultEmpty.classList.add(
        "hidden"
    );


    for (const item of currentItems) {

        const element =
            document.createElement("div");

        element.className = "item";


        const deleteButton =
            document.createElement("button");

        deleteButton.className =
            "deleteItem";

        deleteButton.textContent =
            "×";


        deleteButton.addEventListener(
            "click",
            async event => {

                event.stopPropagation();

                await deleteItem(
                    item.id
                );
            }
        );


        const title =
            document.createElement("div");

        title.className =
            "itemOverlay";

        title.textContent =
            item.name;


        element.appendChild(
            title
        );

        element.appendChild(
            deleteButton
        );


        element.addEventListener(
            "click",
            () => {

                openItem(item);
            }
        );


        /*
            For image/video previews we decrypt the
            actual file only when the user opens it.
        */

        if (item.type.startsWith("image/")) {

            decryptToBlob(
                item
            ).then(blob => {

                const url =
                    URL.createObjectURL(blob);

                const img =
                    document.createElement("img");

                img.src = url;

                element.prepend(img);

            }).catch(console.error);
        }


        itemsGrid.appendChild(
            element
        );
    }
}


/* ==========================================================
   DECRYPT FILE
   ========================================================== */

async function decryptToBlob(item) {

    const data =
        await decryptData(
            item.encrypted,
            currentKey
        );


    return new Blob(
        [data],
        {
            type: item.type
        }
    );
}


/* ==========================================================
   OPEN ITEM
   ========================================================== */

async function openItem(item) {

    try {

        const blob =
            await decryptToBlob(item);


        const url =
            URL.createObjectURL(blob);


        previewImage.classList.add(
            "hidden"
        );

        previewVideo.classList.add(
            "hidden"
        );


        if (
            item.type.startsWith(
                "image/"
            )
        ) {

            previewImage.src =
                url;

            previewImage.classList.remove(
                "hidden"
            );

        } else if (
            item.type.startsWith(
                "video/"
            )
        ) {

            previewVideo.src =
                url;

            previewVideo.classList.remove(
                "hidden"
            );
        }


        let info =
            `Файл: ${item.name}\n` +
            `Размер: ${formatBytes(item.size)}\n` +
            `Дата: ${new Date(item.createdAt).toLocaleString()}`;


        if (item.location) {

            info +=
                `\n\n📍 Координаты\n` +
                `${item.location.latitude}, ` +
                `${item.location.longitude}`;


            if (item.location.accuracy) {

                info +=
                    `\nТочность: ±` +
                    `${Math.round(item.location.accuracy)} м`;
            }
        }


        previewInfo.textContent =
            info;


        previewModal.classList.remove(
            "hidden"
        );

    } catch (error) {

        console.error(error);

        showToast(
            "Не удалось расшифровать файл."
        );
    }
}


/* ==========================================================
   DELETE
   ========================================================== */

async function deleteItem(id) {

    if (
        !confirm(
            "Удалить зашифрованный файл?"
        )
    ) {

        return;
    }


    await dbDelete(
        "items",
        id
    );


    await loadItems();

    showToast(
        "Файл удалён."
    );
}


/* ==========================================================
   FORMAT BYTES
   ========================================================== */

function formatBytes(bytes) {

    if (bytes === 0) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB"
    ];

    const index =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );

    return (
        parseFloat(
            (
                bytes /
                Math.pow(
                    1024,
                    index
                )
            ).toFixed(1)
        ) +
        " " +
        units[index]
    );
}


/* ==========================================================
   CAMERA
   ========================================================== */

$("cameraButton").addEventListener(
    "click",
    startCamera
);


async function startCamera() {

    try {

        /*
            Request location first.
        */

        currentLocation =
            await getLocation();


        /*
            Request camera.
        */

        cameraStream =
            await navigator.mediaDevices.getUserMedia(
                {
                    video: {
                        facingMode: {
                            ideal: "environment"
                        }
                    },

                    audio: false
                }
            );


        cameraPreview.srcObject =
            cameraStream;


        cameraScreen.classList.remove(
            "hidden"
        );


        updateGPSUI();

    } catch (error) {

        console.error(error);

        showToast(
            "Не удалось получить камеру или GPS."
        );
    }
}


/* ==========================================================
   GPS
   ========================================================== */

function getLocation() {

    return new Promise(
        (resolve, reject) => {

            if (!navigator.geolocation) {

                reject(
                    new Error(
                        "Геолокация недоступна."
                    )
                );

                return;
            }


            navigator.geolocation.getCurrentPosition(

                position => {

                    resolve({
                        latitude:
                            position.coords.latitude,

                        longitude:
                            position.coords.longitude,

                        accuracy:
                            position.coords.accuracy,

                        altitude:
                            position.coords.altitude,

                        heading:
                            position.coords.heading,

                        speed:
                            position.coords.speed,

                        timestamp:
                            position.timestamp
                    });
                },


                error => {

                    reject(error);
                },


                {
                    enableHighAccuracy: true,

                    timeout: 10000,

                    maximumAge: 0
                }
            );
        }
    );
}


function updateGPSUI() {

    if (!currentLocation) {

        gpsIndicator.classList.remove(
            "good"
        );

        gpsText.textContent =
            "GPS недоступен.";

        return;
    }


    gpsIndicator.classList.add(
        "good"
    );


    gpsText.textContent =
        `GPS ±${Math.round(
            currentLocation.accuracy
        )} м`;
}


/* ==========================================================
   TAKE PHOTO
   ========================================================== */

$("takePhoto").addEventListener(
    "click",
    takePhoto
);


async function takePhoto() {

    if (!cameraStream) {

        return;
    }


    const video =
        cameraPreview;


    const canvas =
        document.createElement(
            "canvas"
        );


    canvas.width =
        video.videoWidth;

    canvas.height =
        video.videoHeight;


    const context =
        canvas.getContext(
            "2d"
        );


    context.drawImage(
        video,
        0,
        0,
        canvas.width,
        canvas.height
    );


    const blob =
        await new Promise(
            resolve =>
                canvas.toBlob(
                    resolve,
                    "image/jpeg",
                    0.92
                )
        );


    if (!blob) {

        showToast(
            "Не удалось создать фотографию."
        );

        return;
    }


    const file =
        new File(
            [
                blob
            ],
            `IMG_${Date.now()}.jpg`,
            {
                type:
                    "image/jpeg"
            }
        );


    await encryptAndStoreFile(
        file,
        currentLocation
    );


    await loadItems();

    closeCamera();

    showToast(
        "Фото зашифровано."
    );
}


/* ==========================================================
   CLOSE CAMERA
   ========================================================== */

$("closeCamera").addEventListener(
    "click",
    closeCamera
);


function closeCamera() {

    if (cameraStream) {

        for (
            const track
            of cameraStream.getTracks()
        ) {

            track.stop();
        }

        cameraStream = null;
    }


    cameraPreview.srcObject =
        null;


    cameraScreen.classList.add(
        "hidden"
    );
}


/* ==========================================================
   PREVIEW CLOSE
   ========================================================== */

$("closePreview").addEventListener(
    "click",
    () => {

        previewModal.classList.add(
            "hidden"
        );

        previewImage.src = "";

        previewVideo.pause();

        previewVideo.src = "";
    }
);


/* ==========================================================
   BIOMETRIC
   ========================================================== */

/*
    WebAuthn/passkeys are the browser-native route toward
    platform authentication.

    This version keeps the PIN as the actual vault key
    unlock mechanism. A later version can add a WebAuthn
    credential as a second authentication layer.
*/

function updateBiometricButton() {

    /*
        Safari/PWA does not expose Face ID to JavaScript
        as a simple "Face ID API".

        WebAuthn is the proper browser API.
    */

    if (
        window.PublicKeyCredential &&
        typeof PublicKeyCredential
            .isUserVerifyingPlatformAuthenticatorAvailable
            === "function"
    ) {

        PublicKeyCredential
            .isUserVerifyingPlatformAuthenticatorAvailable()
            .then(available => {

                if (available) {

                    biometricButton.classList.remove(
                        "hidden"
                    );

                    biometricButton.textContent =
                        "Face ID / код устройства";

                } else {

                    biometricButton.classList.add(
                        "hidden"
                    );
                }
            });
    }
}


/*
    Important:
    A real WebAuthn implementation needs a relying-party
    server/domain and challenge management.

    Therefore this prototype deliberately doesn't pretend
    that a simple JavaScript button equals secure Face ID.
*/


biometricButton.addEventListener(
    "click",
    () => {

        showToast(
            "Для WebAuthn нужен отдельный passkey-регистрационный слой."
        );
    }
);


/* ==========================================================
   AUTO LOCK
   ========================================================== */

document.addEventListener(
    "visibilitychange",
    () => {

        if (
            document.visibilityState !==
            "visible"
        ) {

            /*
                Drop the in-memory CryptoKey.
            */

            currentKey = null;

            /*
                Do not keep camera active.
            */

            closeCamera();

            /*
                Hide vault.
            */

            if (
                !vaultScreen.classList.contains(
                    "hidden"
                )
            ) {

                vaultScreen.classList.add(
                    "hidden"
                );

                lockScreen.classList.remove(
                    "hidden"
                );
            }
        }
    }
);


/* ==========================================================
   PWA SERVICE WORKER
   ========================================================== */

if (
    "serviceWorker"
    in navigator
) {

    window.addEventListener(
        "load",
        () => {

            navigator.serviceWorker
                .register("./sw.js")
                .catch(
                    console.error
                );
        }
    );
}


/* ==========================================================
   INITIALIZE
   ========================================================== */

initialize().catch(
    error => {

        console.error(error);

        lockMessage.textContent =
            "Не удалось инициализировать DualVault.";
    }
);