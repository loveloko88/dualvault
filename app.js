"use strict";

const DB_NAME = "DualVaultDB";
const DB_VERSION = 1;

const VAULT_A = "A";
const VAULT_B = "B";

const PBKDF2_ITERATIONS = 150000;

let currentVault = VAULT_A;
let currentKey = null;

let cameraStream = null;
let currentLocation = null;
let currentItems = [];

let openedItem = null;
let openedObjectUrl = null;

let editorImage = null;
let editorOverlay = null;
let editorStrokes = [];
let editorDrawing = false;
let editorLastPoint = null;
let editorEraser = false;

const $ = id => document.getElementById(id);

const el = {
    lockScreen: $("lockScreen"),
    vaultScreen: $("vaultScreen"),

    setupBlock: $("setupBlock"),
    unlockBlock: $("unlockBlock"),

    setupPinA: $("setupPinA"),
    setupPinB: $("setupPinB"),

    unlockPin: $("unlockPin"),
    lockMessage: $("lockMessage"),

    selectA: $("selectA"),
    selectB: $("selectB"),

    unlockButton: $("unlockButton"),
    createVaults: $("createVaults"),

    biometricButton: $("biometricButton"),

    vaultTitle: $("vaultTitle"),

    fileInput: $("fileInput"),

    cameraScreen: $("cameraScreen"),
    cameraPreview: $("cameraPreview"),

    gpsText: $("gpsText"),
    gpsIndicator: $("gpsIndicator"),

    previewModal: $("previewModal"),
    previewImage: $("previewImage"),
    previewVideo: $("previewVideo"),
    previewInfo: $("previewInfo"),
    editPhotoButton: $("editPhotoButton"),

    editorModal: $("editorModal"),
    editorCanvas: $("editorCanvas"),
    editorColor: $("editorColor"),
    editorSize: $("editorSize"),
    editorEraser: $("editorEraser"),
    editorUndo: $("editorUndo"),
    editorClear: $("editorClear"),
    editorSave: $("editorSave"),
    editorClose: $("editorClose"),

    itemsGrid: $("itemsGrid"),
    vaultEmpty: $("vaultEmpty"),

    toast: $("toast")
};


/* ==========================================================
   UTILITY
   ========================================================== */

function randomBytes(length) {

    const bytes = new Uint8Array(length);

    crypto.getRandomValues(bytes);

    return bytes;
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


function showToast(message) {

    el.toast.textContent = message;

    el.toast.classList.remove("hidden");

    clearTimeout(showToast.timer);

    showToast.timer = setTimeout(() => {

        el.toast.classList.add("hidden");

    }, 2600);
}


function formatBytes(bytes) {

    if (bytes < 1024) {

        return `${bytes} Б`;
    }

    const units = ["КБ", "МБ", "ГБ"];

    let value = bytes / 1024;

    let index = 0;

    while (
        value >= 1024 &&
        index < units.length - 1
    ) {

        value /= 1024;
        index++;
    }

    return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}


function formatCoordinate(value) {

    return Number(value).toFixed(5);
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


async function dbPut(store, value) {

    const db = await openDB();

    return new Promise((resolve, reject) => {

        const tx = db.transaction(
            store,
            "readwrite"
        );

        tx.objectStore(store).put(value);

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


async function dbGet(store, key) {

    const db = await openDB();

    return new Promise((resolve, reject) => {

        const tx = db.transaction(
            store,
            "readonly"
        );

        const request =
            tx.objectStore(store).get(key);

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


async function dbDelete(store, key) {

    const db = await openDB();

    return new Promise((resolve, reject) => {

        const tx = db.transaction(
            store,
            "readwrite"
        );

        tx.objectStore(store).delete(key);

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


async function dbGetAll(store) {

    const db = await openDB();

    return new Promise((resolve, reject) => {

        const tx = db.transaction(
            store,
            "readonly"
        );

        const request =
            tx.objectStore(store).getAll();

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

async function deriveKeyFromPIN(pin, salt) {

    const rawKey =
        await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(pin),
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
        rawKey,
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


async function decryptData(record, key) {

    return crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: base64ToBytes(record.iv)
        },
        key,
        base64ToBytes(record.data)
    );
}


/* ==========================================================
   VAULT
   ========================================================== */

async function getVaultConfig(vault) {

    return dbGet(
        "settings",
        `vault-${vault}`
    );
}


async function setupVault(vault, pin) {

    const salt = randomBytes(16);

    const pinKey =
        await deriveKeyFromPIN(
            pin,
            salt
        );

    const vaultBytes =
        randomBytes(32);

    const encryptedVaultKey =
        await encryptData(
            vaultBytes,
            pinKey
        );

    const verifier =
        await encryptData(
            new TextEncoder().encode(
                "DUALVAULT_VERIFIER"
            ),
            pinKey
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
}


async function unlockVault(vault, pin) {

    const config =
        await getVaultConfig(vault);

    if (!config) {

        throw new Error(
            "Пространство ещё не создано."
        );
    }

    const salt =
        base64ToBytes(
            config.salt
        );

    const pinKey =
        await deriveKeyFromPIN(
            pin,
            salt
        );

    try {

        const verifier =
            await decryptData(
                config.verifier,
                pinKey
            );

        const verifierText =
            new TextDecoder().decode(
                verifier
            );

        if (
            verifierText !==
            "DUALVAULT_VERIFIER"
        ) {

            throw new Error();
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


async function initialize() {

    const [a, b] =
        await Promise.all([
            getVaultConfig(VAULT_A),
            getVaultConfig(VAULT_B)
        ]);

    if (a && b) {

        el.setupBlock.classList.add(
            "hidden"
        );

        el.unlockBlock.classList.remove(
            "hidden"
        );

    } else {

        el.setupBlock.classList.remove(
            "hidden"
        );

        el.unlockBlock.classList.add(
            "hidden"
        );
    }
}


/* ==========================================================
   CREATE VAULTS
   ========================================================== */

el.createVaults.onclick = async () => {

    const pinA =
        el.setupPinA.value.trim();

    const pinB =
        el.setupPinB.value.trim();

    if (
        pinA.length < 4 ||
        pinB.length < 4
    ) {

        el.lockMessage.textContent =
            "PIN должен содержать минимум 4 символа.";

        return;
    }

    if (pinA === pinB) {

        el.lockMessage.textContent =
            "PIN двух пространств должны отличаться.";

        return;
    }

    el.createVaults.disabled = true;

    try {

        await setupVault(
            VAULT_A,
            pinA
        );

        await setupVault(
            VAULT_B,
            pinB
        );

        el.setupPinA.value = "";
        el.setupPinB.value = "";

        el.lockMessage.textContent = "";

        showToast(
            "Пространства созданы."
        );

        await initialize();

    } catch (error) {

        console.error(error);

        el.lockMessage.textContent =
            "Не удалось создать хранилища.";

    } finally {

        el.createVaults.disabled = false;
    }
};


/* ==========================================================
   VAULT SELECT
   ========================================================== */

el.selectA.onclick = () => {

    selectVault(VAULT_A);
};


el.selectB.onclick = () => {

    selectVault(VAULT_B);
};


function selectVault(vault) {

    currentVault = vault;

    el.selectA.classList.toggle(
        "active",
        vault === VAULT_A
    );

    el.selectB.classList.toggle(
        "active",
        vault === VAULT_B
    );
}


/* ==========================================================
   UNLOCK
   ========================================================== */

el.unlockButton.onclick = async () => {

    const pin =
        el.unlockPin.value.trim();

    if (!pin) {

        el.lockMessage.textContent =
            "Введи PIN.";

        return;
    }

    el.unlockButton.disabled = true;

    try {

        await unlockVault(
            currentVault,
            pin
        );

        el.unlockPin.value = "";

        el.lockMessage.textContent = "";

    } catch (error) {

        el.lockMessage.textContent =
            error.message;

        el.unlockPin.value = "";

    } finally {

        el.unlockButton.disabled = false;
    }
};


/* ==========================================================
   VAULT UI
   ========================================================== */

async function showVault() {

    el.lockScreen.classList.add(
        "hidden"
    );

    el.vaultScreen.classList.remove(
        "hidden"
    );

    el.vaultTitle.textContent =
        currentVault === VAULT_A
            ? "Пространство 1"
            : "Пространство 2";

    await loadItems();
}


function lockVault() {

    currentKey = null;

    currentItems = [];

    el.itemsGrid.innerHTML = "";

    closeCamera();

    closePreview();

    closeEditor();

    el.vaultScreen.classList.add(
        "hidden"
    );

    el.lockScreen.classList.remove(
        "hidden"
    );
}


$("lockButton").onclick = lockVault;


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

    currentItems =
        all
            .filter(
                item =>
                    item.vault === currentVault
            )
            .sort(
                (a, b) =>
                    b.createdAt - a.createdAt
            );

    renderItems();
}


/* ==========================================================
   FILE IMPORT
   ========================================================== */

$("fileButton").onclick = () => {

    el.fileInput.click();
};


el.fileInput.onchange = async event => {

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

    el.fileInput.value = "";

    await loadItems();
};


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

        const arrayBuffer =
            await file.arrayBuffer();

        const encrypted =
            await encryptData(
                arrayBuffer,
                currentKey
            );

        await saveItem({

            id: crypto.randomUUID(),

            vault: currentVault,

            name: file.name,

            type:
                file.type ||
                "application/octet-stream",

            size: file.size,

            createdAt: Date.now(),

            encrypted,

            location:
                location || null
        });

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
   RENDER FILES
   ========================================================== */

function renderItems() {

    el.itemsGrid.innerHTML = "";

    el.vaultEmpty.classList.toggle(
        "hidden",
        currentItems.length > 0
    );

    for (const item of currentItems) {

        const card =
            document.createElement("div");

        card.className = "item";

        const deleteButton =
            document.createElement("button");

        deleteButton.className =
            "deleteItem";

        deleteButton.textContent = "×";

        deleteButton.onclick =
            async event => {

                event.stopPropagation();

                await deleteItem(
                    item.id
                );
            };


        const title =
            document.createElement("div");

        title.className =
            "itemOverlay";

        title.textContent =
            item.name;


        card.append(
            title,
            deleteButton
        );


        card.onclick = () => {

            openItem(item);
        };


        if (
            item.type &&
            item.type.startsWith("image/")
        ) {

            decryptToBlob(item)
                .then(blob => {

                    const img =
                        document.createElement("img");

                    img.src =
                        URL.createObjectURL(
                            blob
                        );

                    img.onload = () => {

                        URL.revokeObjectURL(
                            img.src
                        );
                    };

                    card.prepend(img);
                })
                .catch(console.error);
        }

        el.itemsGrid.appendChild(card);
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
        "Удалено."
    );
}


/* ==========================================================
   PREVIEW
   ========================================================== */

async function openItem(item) {

    openedItem = item;

    try {

        if (openedObjectUrl) {

            URL.revokeObjectURL(
                openedObjectUrl
            );

            openedObjectUrl = null;
        }

        const blob =
            await decryptToBlob(item);

        openedObjectUrl =
            URL.createObjectURL(
                blob
            );

        el.previewImage.classList.add(
            "hidden"
        );

        el.previewVideo.classList.add(
            "hidden"
        );

        el.editPhotoButton.classList.add(
            "hidden"
        );


        if (
            item.type &&
            item.type.startsWith("image/")
        ) {

            el.previewImage.src =
                openedObjectUrl;

            el.previewImage.classList.remove(
                "hidden"
            );

            el.editPhotoButton.classList.remove(
                "hidden"
            );

        } else if (
            item.type &&
            item.type.startsWith("video/")
        ) {

            el.previewVideo.src =
                openedObjectUrl;

            el.previewVideo.classList.remove(
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
                `${formatCoordinate(item.location.latitude)}, ` +
                `${formatCoordinate(item.location.longitude)}\n` +
                `Точность: ±${Math.round(
                    item.location.accuracy || 0
                )} м`;
        }


        el.previewInfo.textContent =
            info;

        el.previewModal.classList.remove(
            "hidden"
        );

    } catch (error) {

        console.error(error);

        showToast(
            "Не удалось расшифровать файл."
        );
    }
}


$("closePreview").onclick =
    closePreview;


function closePreview() {

    el.previewModal.classList.add(
        "hidden"
    );

    el.previewImage.src = "";

    el.previewVideo.pause();

    el.previewVideo.src = "";

    if (openedObjectUrl) {

        URL.revokeObjectURL(
            openedObjectUrl
        );

        openedObjectUrl = null;
    }

    openedItem = null;
}


/* ==========================================================
   PHOTO EDITOR
   ========================================================== */

el.editPhotoButton.onclick =
    openEditor;


el.editorClose.onclick =
    closeEditor;


el.editorUndo.onclick =
    undoEditor;


el.editorClear.onclick =
    clearEditor;


el.editorSave.onclick =
    saveEditedPhoto;


/*
    В новой версии ластик —
    отдельная кнопка.
*/

if (el.editorEraser) {

    el.editorEraser.onclick = () => {

        editorEraser =
            !editorEraser;

        el.editorEraser.classList.toggle(
            "active",
            editorEraser
        );
    };
}


function editorPoint(event) {

    const rect =
        el.editorCanvas.getBoundingClientRect();

    return {

        x:
            (event.clientX - rect.left) *
            (
                el.editorCanvas.width /
                rect.width
            ),

        y:
            (event.clientY - rect.top) *
            (
                el.editorCanvas.height /
                rect.height
            )
    };
}


function redrawEditor() {

    if (!editorImage) {

        return;
    }

    const canvas =
        el.editorCanvas;

    const ctx =
        canvas.getContext("2d");

    ctx.clearRect(
        0,
        0,
        canvas.width,
        canvas.height
    );

    ctx.drawImage(
        editorImage,
        0,
        0
    );


    if (!editorOverlay) {

        editorOverlay =
            document.createElement(
                "canvas"
            );
    }


    editorOverlay.width =
        canvas.width;

    editorOverlay.height =
        canvas.height;


    const overlayContext =
        editorOverlay.getContext("2d");


    for (
        const stroke
        of editorStrokes
    ) {

        overlayContext.save();

        overlayContext.lineCap =
            "round";

        overlayContext.lineJoin =
            "round";

        overlayContext.lineWidth =
            stroke.size;


        overlayContext.globalCompositeOperation =
            stroke.erase
                ? "destination-out"
                : "source-over";


        overlayContext.strokeStyle =
            stroke.color;


        overlayContext.fillStyle =
            stroke.color;


        overlayContext.beginPath();


        if (
            stroke.points.length === 1
        ) {

            const point =
                stroke.points[0];

            overlayContext.arc(
                point.x,
                point.y,
                stroke.size / 2,
                0,
                Math.PI * 2
            );

            overlayContext.fill();

        } else {

            overlayContext.moveTo(
                stroke.points[0].x,
                stroke.points[0].y
            );


            for (
                let i = 1;
                i < stroke.points.length;
                i++
            ) {

                overlayContext.lineTo(
                    stroke.points[i].x,
                    stroke.points[i].y
                );
            }

            overlayContext.stroke();
        }


        overlayContext.restore();
    }


    ctx.drawImage(
        editorOverlay,
        0,
        0
    );
}


async function openEditor() {

    if (
        !openedItem ||
        !openedItem.type.startsWith("image/")
    ) {

        return;
    }

    try {

        const blob =
            await decryptToBlob(
                openedItem
            );

        const url =
            URL.createObjectURL(
                blob
            );

        const image =
            new Image();


        image.onload = () => {

            editorImage =
                image;

            editorStrokes =
                [];

            editorOverlay =
                null;

            el.editorCanvas.width =
                image.naturalWidth;

            el.editorCanvas.height =
                image.naturalHeight;


            redrawEditor();


            el.editorModal.classList.remove(
                "hidden"
            );


            URL.revokeObjectURL(
                url
            );
        };


        image.onerror = () => {

            URL.revokeObjectURL(
                url
            );

            showToast(
                "Не удалось открыть фото."
            );
        };


        image.src = url;

    } catch (error) {

        console.error(error);

        showToast(
            "Не удалось открыть редактор."
        );
    }
}


function closeEditor() {

    el.editorModal.classList.add(
        "hidden"
    );

    editorImage = null;

    editorOverlay = null;

    editorStrokes = [];

    editorDrawing = false;

    editorLastPoint = null;

    editorEraser = false;

    if (el.editorEraser) {

        el.editorEraser.classList.remove(
            "active"
        );
    }
}


/* ==========================================================
   EDITOR DRAWING
   ========================================================== */

el.editorCanvas.onpointerdown =
    event => {

        if (
            el.editorModal.classList.contains(
                "hidden"
            )
        ) {

            return;
        }

        event.preventDefault();

        editorDrawing = true;

        editorLastPoint =
            editorPoint(event);


        el.editorCanvas.setPointerCapture(
            event.pointerId
        );


        editorStrokes.push({

            color:
                el.editorColor.value,

            size:
                Number(
                    el.editorSize.value
                ),

            erase:
                editorEraser,

            points: [
                {
                    x:
                        editorLastPoint.x,

                    y:
                        editorLastPoint.y
                }
            ]
        });


        redrawEditor();
    };


el.editorCanvas.onpointermove =
    event => {

        if (!editorDrawing) {

            return;
        }

        event.preventDefault();

        const point =
            editorPoint(event);

        const stroke =
            editorStrokes[
                editorStrokes.length - 1
            ];


        stroke.points.push({

            x: point.x,

            y: point.y
        });


        editorLastPoint =
            point;


        redrawEditor();
    };


function endStroke() {

    editorDrawing = false;

    editorLastPoint = null;
}


el.editorCanvas.onpointerup =
    endStroke;


el.editorCanvas.onpointercancel =
    endStroke;


el.editorCanvas.onpointerleave =
    endStroke;


/* ==========================================================
   EDITOR UNDO / CLEAR
   ========================================================== */

function undoEditor() {

    if (
        editorStrokes.length === 0
    ) {

        return;
    }

    editorStrokes.pop();

    redrawEditor();
}


function clearEditor() {

    editorStrokes = [];

    redrawEditor();
}


/* ==========================================================
   SAVE EDITED PHOTO
   ========================================================== */

async function saveEditedPhoto() {

    if (
        !openedItem ||
        !editorImage
    ) {

        return;
    }

    el.editorSave.disabled = true;

    try {

        redrawEditor();


        const blob =
            await new Promise(resolve => {

                el.editorCanvas.toBlob(
                    resolve,
                    "image/jpeg",
                    0.92
                );
            });


        if (!blob) {

            throw new Error(
                "Не удалось создать изображение."
            );
        }


        const baseName =
            openedItem.name.replace(
                /\.[^.]+$/,
                ""
            );


        const newFile =
            new File(
                [blob],
                `${baseName}_edited.jpg`,
                {
                    type: "image/jpeg"
                }
            );


        await encryptAndStoreFile(
            newFile,
            openedItem.location || null
        );


        await loadItems();

        closeEditor();

        closePreview();

        showToast(
            "Изменённое фото сохранено."
        );

    } catch (error) {

        console.error(error);

        showToast(
            "Не удалось сохранить фото."
        );

    } finally {

        el.editorSave.disabled = false;
    }
}


/* ==========================================================
   CAMERA
   ========================================================== */

$("cameraButton").onclick =
    startCamera;


$("closeCamera").onclick =
    closeCamera;


$("takePhoto").onclick =
    takePhoto;


async function startCamera() {

    try {

        currentLocation = null;

        el.gpsText.textContent =
            "Получение координат...";

        el.gpsIndicator.classList.remove(
            "good"
        );


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


        el.cameraPreview.srcObject =
            cameraStream;


        el.cameraScreen.classList.remove(
            "hidden"
        );


        getLocation()

            .then(location => {

                currentLocation =
                    location;

                updateGPSUI();
            })

            .catch(() => {

                currentLocation = null;

                el.gpsText.textContent =
                    "GPS недоступен — фото всё равно можно сделать";

                el.gpsIndicator.classList.remove(
                    "good"
                );
            });

    } catch (error) {

        console.error(error);

        showToast(
            "Не удалось открыть камеру. Проверь разрешение камеры."
        );
    }
}


/* ==========================================================
   GPS
   ========================================================== */

function getLocation() {

    return new Promise(
        (resolve, reject) => {

            if (
                !navigator.geolocation
            ) {

                reject(
                    new Error(
                        "GPS недоступен"
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

                reject,

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

        el.gpsText.textContent =
            "GPS недоступен";

        el.gpsIndicator.classList.remove(
            "good"
        );

        return;
    }


    el.gpsIndicator.classList.add(
        "good"
    );


    el.gpsText.textContent =
        `GPS ±${Math.round(
            currentLocation.accuracy || 0
        )} м`;
}


/* ==========================================================
   TAKE PHOTO
   ========================================================== */

async function takePhoto() {

    if (!cameraStream) {

        return;
    }


    const video =
        el.cameraPreview;


    if (!video.videoWidth) {

        showToast(
            "Камера ещё запускается."
        );

        return;
    }


    const canvas =
        document.createElement(
            "canvas"
        );


    canvas.width =
        video.videoWidth;

    canvas.height =
        video.videoHeight;


    const ctx =
        canvas.getContext("2d");


    ctx.drawImage(
        video,
        0,
        0,
        canvas.width,
        canvas.height
    );


    /*
        Координаты вшиваются
        прямо в JPEG.
    */

    if (currentLocation) {

        drawLocationStamp(
            ctx,
            canvas.width,
            canvas.height,
            currentLocation
        );
    }


    const blob =
        await new Promise(resolve => {

            canvas.toBlob(
                resolve,
                "image/jpeg",
                0.92
            );
        });


    if (!blob) {

        showToast(
            "Не удалось создать фото."
        );

        return;
    }


    const locationForFile =
        currentLocation;


    await encryptAndStoreFile(

        new File(
            [blob],
            `IMG_${Date.now()}.jpg`,
            {
                type: "image/jpeg"
            }
        ),

        locationForFile
    );


    await loadItems();

    closeCamera();


    showToast(
        locationForFile
            ? "Фото сохранено с координатами."
            : "Фото сохранено без GPS."
    );
}


/* ==========================================================
   GPS STAMP
   ========================================================== */

function drawLocationStamp(
    ctx,
    width,
    height,
    location
) {

    if (
        !location ||
        !Number.isFinite(
            Number(location.latitude)
        ) ||
        !Number.isFinite(
            Number(location.longitude)
        )
    ) {

        return;
    }


    const scale =
        Math.max(
            1,
            Math.min(
                width,
                height
            ) / 900
        );


    const padding =
        Math.round(
            12 * scale
        );


    const fontSize =
        Math.round(
            20 * scale
        );


    const smallFontSize =
        Math.round(
            15 * scale
        );


    const lineHeight =
        Math.round(
            25 * scale
        );


    const coordinates =
        `${formatCoordinate(
            location.latitude
        )}, ${formatCoordinate(
            location.longitude
        )}`;


    const accuracy =
        `GPS ±${Math.round(
            location.accuracy || 0
        )} м`;


    ctx.save();


    ctx.font =
        `600 ${fontSize}px -apple-system, BlinkMacSystemFont, Arial, sans-serif`;


    const textWidth =
        Math.max(
            ctx.measureText(
                coordinates
            ).width,

            ctx.measureText(
                accuracy
            ).width
        );


    const boxWidth =
        textWidth +
        padding * 2;


    const boxHeight =
        lineHeight * 2 +
        padding * 2;


    /*
        Чёрная полупрозрачная
        плашка в левом верхнем углу.
    */

    ctx.fillStyle =
        "rgba(0,0,0,.70)";


    ctx.fillRect(
        padding,
        padding,
        boxWidth,
        boxHeight
    );


    ctx.fillStyle =
        "#ffffff";


    ctx.textBaseline =
        "top";


    ctx.fillText(
        coordinates,

        padding * 1.6,

        padding +
        2 * scale
    );


    ctx.globalAlpha =
        0.82;


    ctx.font =
        `500 ${smallFontSize}px -apple-system, BlinkMacSystemFont, Arial, sans-serif`;


    ctx.fillText(
        accuracy,

        padding * 1.6,

        padding +
        lineHeight +
        2 * scale
    );


    ctx.restore();
}


/* ==========================================================
   CLOSE CAMERA
   ========================================================== */

function closeCamera() {

    if (cameraStream) {

        cameraStream
            .getTracks()
            .forEach(track => {

                track.stop();
            });

        cameraStream = null;
    }


    el.cameraPreview.srcObject =
        null;


    el.cameraScreen.classList.add(
        "hidden"
    );
}


/* ==========================================================
   BIOMETRIC
   ========================================================== */

el.biometricButton.classList.add(
    "hidden"
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
            &&
            currentKey
        ) {

            currentKey = null;

            closeCamera();

            closePreview();

            closeEditor();

            el.vaultScreen.classList.add(
                "hidden"
            );

            el.lockScreen.classList.remove(
                "hidden"
            );
        }
    }
);


/* ==========================================================
   SERVICE WORKER
   ========================================================== */

if (
    "serviceWorker" in navigator
) {

    window.addEventListener(
        "load",
        () => {

            navigator.serviceWorker
                .register("./sw.js")
                .catch(console.error);
        }
    );
}


/* ==========================================================
   START
   ========================================================== */

initialize().catch(error => {

    console.error(error);

    el.lockMessage.textContent =
        "Не удалось инициализировать DualVault.";
});