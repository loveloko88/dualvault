"use strict";

const DB="DualVaultDB", VER=1, A="A", B="B", ITER=150000;
let vault=A,key=null,stream=null,locationData=null,items=[],opened=null,editImg=null,drawing=false,last=null,history=[];

const $=id=>document.getElementById(id);
const lock=$("lockScreen"), vaultScreen=$("vaultScreen");
const setup=$("setupBlock"), unlock=$("unlockBlock");
const pinA=$("setupPinA"),pinB=$("setupPinB"),unlockPin=$("unlockPin");
const msg=$("lockMessage"),selA=$("selectA"),selB=$("selectB");
const unlockBtn=$("unlockButton"),create=$("createVaults"),bio=$("biometricButton");
const title=$("vaultTitle"),fileInput=$("fileInput");
const camera=$("cameraScreen"),video=$("cameraPreview");
const gpsText=$("gpsText"),gpsInd=$("gpsIndicator");
const preview=$("previewModal"),previewImg=$("previewImage"),previewVid=$("previewVideo"),info=$("previewInfo");
const editor=$("editorModal"),canvas=$("editorCanvas"),color=$("editorColor"),size=$("editorSize");
const undo=$("editorUndo"),clear=$("editorClear"),save=$("editorSave"),closeEdit=$("editorClose");
const grid=$("itemsGrid"),empty=$("vaultEmpty"),toast=$("toast");

function toastMsg(s){
 toast.textContent=s;toast.classList.remove("hidden");
 clearTimeout(toastMsg.t);toastMsg.t=setTimeout(()=>toast.classList.add("hidden"),2500);
}
function rnd(n){let x=new Uint8Array(n);crypto.getRandomValues(x);return x}
function b64(x){let s="";for(let i=0;i<x.length;i+=0x8000)s+=String.fromCharCode(...x.subarray(i,i+0x8000));return btoa(s)}
function unb64(s){let x=atob(s),a=new Uint8Array(x.length);for(let i=0;i<x.length;i++)a[i]=x.charCodeAt(i);return a}

function db(){
 return new Promise((res,rej)=>{
  let r=indexedDB.open(DB,VER);
  r.onupgradeneeded=e=>{
   let d=e.target.result;
   if(!d.objectStoreNames.contains("settings"))d.createObjectStore("settings",{keyPath:"key"});
   if(!d.objectStoreNames.contains("items"))d.createObjectStore("items",{keyPath:"id"});
  };
  r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);
 });
}
async function put(store,v){
 let d=await db();return new Promise((res,rej)=>{
  let t=d.transaction(store,"readwrite");t.objectStore(store).put(v);
  t.oncomplete=()=>{d.close();res()};t.onerror=()=>{d.close();rej(t.error)}
 });
}
async function get(store,k){
 let d=await db();return new Promise((res,rej)=>{
  let t=d.transaction(store,"readonly"),r=t.objectStore(store).get(k);
  r.onsuccess=()=>{d.close();res(r.result)};r.onerror=()=>{d.close();rej(r.error)}
 });
}
async function all(store){
 let d=await db();return new Promise((res,rej)=>{
  let t=d.transaction(store,"readonly"),r=t.objectStore(store).getAll();
  r.onsuccess=()=>{d.close();res(r.result)};r.onerror=()=>{d.close();rej(r.error)}
 });
}
async function del(store,k){
 let d=await db();return new Promise((res,rej)=>{
  let t=d.transaction(store,"readwrite");t.objectStore(store).delete(k);
  t.oncomplete=()=>{d.close();res()};t.onerror=()=>{d.close();rej(t.error)}
 });
}

async function derive(pin,salt){
 let p=await crypto.subtle.importKey("raw",new TextEncoder().encode(pin),"PBKDF2",false,["deriveKey"]);
 return crypto.subtle.deriveKey(
  {name:"PBKDF2",salt,iterations:ITER,hash:"SHA-256"},
  p,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]
 );
}
async function enc(data,k){
 let iv=rnd(12),x=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,data);
 return {iv:b64(iv),data:b64(new Uint8Array(x))}
}
async function dec(o,k){
 return crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(o.iv)},k,unb64(o.data))
}

async function config(v){return get("settings","vault-"+v)}

async function setupVault(v,pin){
 let salt=rnd(16),pk=await derive(pin,salt),vk=rnd(32);
 let encryptedVaultKey=await enc(vk,pk);
 let verifier=await enc(new TextEncoder().encode("DUALVAULT"),pk);
 await put("settings",{key:"vault-"+v,salt:b64(salt),encryptedVaultKey,verifier});
}

async function unlockVault(v,pin){
 let c=await config(v);if(!c)throw Error("Пространство ещё не создано.");
 try{
  let pk=await derive(pin,unb64(c.salt));
  let test=new TextDecoder().decode(await dec(c.verifier,pk));
  if(test!=="DUALVAULT")throw Error();
  let raw=await dec(c.encryptedVaultKey,pk);
  key=await crypto.subtle.importKey("raw",raw,{name:"AES-GCM"},false,["encrypt","decrypt"]);
  vault=v;await showVault();
 }catch(e){throw Error("Неверный PIN.")}
}

async function init(){
 let a=await config(A),b=await config(B);
 if(a&&b){setup.classList.add("hidden");unlock.classList.remove("hidden")}
 else{setup.classList.remove("hidden");unlock.classList.add("hidden")}
}
create.addEventListener("click",async()=>{
 let a=pinA.value.trim(),b=pinB.value.trim();
 if(a.length<4||b.length<4)return msg.textContent="PIN должен содержать минимум 4 символа.";
 if(a===b)return msg.textContent="PIN двух пространств должны отличаться.";
 try{
  create.disabled=true;await setupVault(A,a);await setupVault(B,b);
  pinA.value=pinB.value="";msg.textContent="";toastMsg("Пространства созданы.");await init();
 }catch(e){msg.textContent="Не удалось создать хранилища."}
 finally{create.disabled=false}
});

selA.addEventListener("click",()=>{vault=A;selA.classList.add("active");selB.classList.remove("active");updateBio()});
selB.addEventListener("click",()=>{vault=B;selB.classList.add("active");selA.classList.remove("active");updateBio()});

unlockBtn.addEventListener("click",async()=>{
 let p=unlockPin.value.trim();if(!p)return msg.textContent="Введи PIN.";
 try{unlockBtn.disabled=true;await unlockVault(vault,p);unlockPin.value="";msg.textContent=""}
 catch(e){msg.textContent=e.message;unlockPin.value=""}
 finally{unlockBtn.disabled=false}
});

async function showVault(){
 lock.classList.add("hidden");vaultScreen.classList.remove("hidden");
 title.textContent=vault===A?"Пространство 1":"Пространство 2";
 await loadItems();
}
function lockVault(){
 key=null;items=[];grid.innerHTML="";vaultScreen.classList.add("hidden");lock.classList.remove("hidden");
}
$("lockButton").addEventListener("click",lockVault);

async function loadItems(){
 items=(await all("items")).filter(x=>x.vault===vault).sort((a,b)=>b.createdAt-a.createdAt);
 render();
}
async function encryptFile(file,loc){
 if(!key)return;
 try{
  let encrypted=await enc(await file.arrayBuffer(),key);
  await put("items",{
   id:crypto.randomUUID(),vault,name:file.name,type:file.type||"application/octet-stream",
   size:file.size,createdAt:Date.now(),encrypted,location:loc||null
  });
 }catch(e){console.error(e);toastMsg("Ошибка шифрования.")}
}

$("fileButton").addEventListener("click",()=>fileInput.click());
fileInput.addEventListener("change",async e=>{
 for(const f of Array.from(e.target.files||[]))await encryptFile(f,null);
 fileInput.value="";await loadItems();toastMsg("Файл зашифрован.");
});

async function blob(item){
 return new Blob([await dec(item.encrypted,key)],{type:item.type});
}

function render(){
 grid.innerHTML="";
 if(!items.length){empty.classList.remove("hidden");return}
 empty.classList.add("hidden");
 for(const item of items){
  let el=document.createElement("div");el.className="item";
  let t=document.createElement("div");t.className="itemOverlay";t.textContent=item.name;
  let d=document.createElement("button");d.className="deleteItem";d.textContent="×";
  d.onclick=async e=>{e.stopPropagation();if(confirm("Удалить зашифрованный файл?")){await del("items",item.id);await loadItems();toastMsg("Файл удалён.")}};
  el.append(t,d);el.onclick=()=>openItem(item);
  if(item.type.startsWith("image/")){
   blob(item).then(b=>{let im=document.createElement("img");im.src=URL.createObjectURL(b);el.prepend(im)}).catch(console.error);
  }
  grid.appendChild(el);
 }
}

function coord(v){return Number(v).toFixed(5)}

async function openItem(item){
 opened=item;
 try{
  let b=await blob(item),u=URL.createObjectURL(b);
  previewImg.classList.add("hidden");previewVid.classList.add("hidden");
  $("editPhotoButton").classList.add("hidden");
  if(item.type.startsWith("image/")){
   previewImg.src=u;previewImg.classList.remove("hidden");$("editPhotoButton").classList.remove("hidden");
  }else if(item.type.startsWith("video/")){
   previewVid.src=u;previewVid.classList.remove("hidden");
  }
  let s=`Файл: ${item.name}\nРазмер: ${bytes(item.size)}\nДата: ${new Date(item.createdAt).toLocaleString()}`;
  if(item.location)s+=`\n\n📍 Координаты\n${coord(item.location.latitude)}, ${coord(item.location.longitude)}${item.location.accuracy?`\nТочность: ±${Math.round(item.location.accuracy)} м`:""}`;
  info.textContent=s;preview.classList.remove("hidden");
 }catch(e){console.error(e);toastMsg("Не удалось расшифровать файл.")}
}

function bytes(n){
 if(!n)return"0 B";
 let u=["B","KB","MB","GB"],i=Math.floor(Math.log(n)/Math.log(1024));
 return (n/Math.pow(1024,i)).toFixed(i?1:0)+" "+u[i];
}

/* ===================== РЕДАКТОР ===================== */

$("editPhotoButton").addEventListener("click",openEditor);
closeEdit.addEventListener("click",closeEditor);
undo.addEventListener("click",undoEdit);
clear.addEventListener("click",clearEdit);
save.addEventListener("click",saveEdit);

async function openEditor(){
 if(!opened||!opened.type.startsWith("image/"))return;
 try{
  let b=await blob(opened),u=URL.createObjectURL(b),im=new Image();
  im.onload=()=>{
   editImg=im;history=[];
   canvas.width=im.naturalWidth;canvas.height=im.naturalHeight;
   canvas.getContext("2d").drawImage(im,0,0);
   editor.classList.remove("hidden");URL.revokeObjectURL(u);
  };
  im.src=u;
 }catch(e){console.error(e);toastMsg("Не удалось открыть редактор.")}
}

function point(e){
 let r=canvas.getBoundingClientRect();
 return{x:(e.clientX-r.left)*canvas.width/r.width,y:(e.clientY-r.top)*canvas.height/r.height}
}
function snap(){
 try{
  history.push(canvas.getContext("2d").getImageData(0,0,canvas.width,canvas.height));
  if(history.length>15)history.shift();
 }catch(e){}
}
canvas.addEventListener("pointerdown",e=>{
 snap();drawing=true;last=point(e);canvas.setPointerCapture(e.pointerId)
});
canvas.addEventListener("pointermove",e=>{
 if(!drawing)return;
 let p=point(e),c=canvas.getContext("2d");
 c.save();c.lineCap="round";c.lineJoin="round";c.lineWidth=Number(size.value);
 c.globalCompositeOperation=color.value==="eraser"?"destination-out":"source-over";
 c.strokeStyle=color.value==="eraser"?"rgba(0,0,0,1)":color.value;
 c.beginPath();c.moveTo(last.x,last.y);c.lineTo(p.x,p.y);c.stroke();c.restore();last=p;
});
["pointerup","pointercancel","pointerleave"].forEach(x=>canvas.addEventListener(x,()=>{drawing=false;last=null}));

function undoEdit(){
 let x=history.pop();if(x)canvas.getContext("2d").putImageData(x,0,0);
}
function clearEdit(){
 if(!editImg)return;snap();
 let c=canvas.getContext("2d");c.clearRect(0,0,canvas.width,canvas.height);c.drawImage(editImg,0,0);
}
function closeEditor(){
 editor.classList.add("hidden");drawing=false;last=null;history=[];editImg=null;
}
async function saveEdit(){
 if(!opened)return;
 let b=await new Promise(r=>canvas.toBlob(r,"image/jpeg",.92));
 if(!b)return;
 let name=opened.name.replace(/\.[^.]+$/,"")+"_edited.jpg";
 await encryptFile(new File([b],name,{type:"image/jpeg"}),opened.location);
 await loadItems();closeEditor();preview.classList.add("hidden");toastMsg("Изменённое фото сохранено.");
}

/* ===================== КАМЕРА ===================== */

$("cameraButton").addEventListener("click",startCamera);
$("closeCamera").addEventListener("click",closeCamera);
$("takePhoto").addEventListener("click",takePhoto);

async function startCamera(){
 try{
  locationData=await getGPS();
  stream=await navigator.mediaDevices.getUserMedia({
   video:{facingMode:{ideal:"environment"}},audio:false
  });
  video.srcObject=stream;camera.classList.remove("hidden");updateGPS();
 }catch(e){console.error(e);toastMsg("Не удалось получить камеру или GPS.")}
}

function getGPS(){
 return new Promise((res,rej)=>{
  if(!navigator.geolocation)return rej(Error("GPS недоступен"));
  navigator.geolocation.getCurrentPosition(
   p=>res({
    latitude:p.coords.latitude,longitude:p.coords.longitude,
    accuracy:p.coords.accuracy,altitude:p.coords.altitude,
    heading:p.coords.heading,speed:p.coords.speed,timestamp:p.timestamp
   }),
   rej,{enableHighAccuracy:true,timeout:10000,maximumAge:0}
  );
 });
}

function updateGPS(){
 if(!locationData){
  gpsInd.classList.remove("good");gpsText.textContent="GPS недоступен.";return
 }
 gpsInd.classList.add("good");gpsText.textContent=`GPS ±${Math.round(locationData.accuracy)} м`;
}

async function takePhoto(){
 if(!stream)return;
 let c=document.createElement("canvas"),v=video;
 c.width=v.videoWidth;c.height=v.videoHeight;
 let x=c.getContext("2d");x.drawImage(v,0,0,c.width,c.height);
 if(locationData)stamp(x,c.width,c.height,locationData);
 let b=await new Promise(r=>c.toBlob(r,"image/jpeg",.92));
 if(!b)return toastMsg("Не удалось создать фотографию.");
 await encryptFile(new File([b],`IMG_${Date.now()}.jpg`,{type:"image/jpeg"}),locationData);
 await loadItems();closeCamera();toastMsg("Фото зашифровано.");
}

function stamp(c,w,h,l){
 if(!l)return;
 let sc=Math.max(1,Math.min(w,h)/900),p=Math.round(14*sc),fs=Math.round(22*sc),lh=Math.round(29*sc);
 let a=`${coord(l.latitude)}, ${coord(l.longitude)}`,b=l.accuracy?`GPS ±${Math.round(l.accuracy)} м`:"GPS";
 c.save();c.font=`600 ${fs}px -apple-system,BlinkMacSystemFont,Arial,sans-serif`;
 let tw=Math.max(c.measureText(a).width,c.measureText(b).width);
 c.fillStyle="rgba(0,0,0,.68)";c.fillRect(p,p,tw+p*2,lh*2+p*2);
 c.fillStyle="#fff";c.textBaseline="top";c.fillText(a,p*2,p+4*sc);
 c.globalAlpha=.82;c.font=`500 ${Math.round(fs*.78)}px -apple-system,BlinkMacSystemFont,Arial,sans-serif`;
 c.fillText(b,p*2,p+lh+2*sc);c.restore();
}

function closeCamera(){
 if(stream){stream.getTracks().forEach(t=>t.stop());stream=null}
 video.srcObject=null;camera.classList.add("hidden");
}

$("closePreview").addEventListener("click",()=>{
 preview.classList.add("hidden");previewImg.src="";previewVid.pause();previewVid.src="";opened=null;
});

function updateBio(){
 if(!window.PublicKeyCredential)return;
 if(typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable==="function"){
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(ok=>{
   if(ok){bio.classList.remove("hidden");bio.textContent="Face ID / код устройства"}
  });
 }
}
bio.addEventListener("click",()=>toastMsg("WebAuthn пока не подключён."));

document.addEventListener("visibilitychange",()=>{
 if(document.visibilityState!=="visible"){
  key=null;closeCamera();
  if(!vaultScreen.classList.contains("hidden")){
   vaultScreen.classList.add("hidden");lock.classList.remove("hidden");
  }
 }
});

if("serviceWorker" in navigator){
 window.addEventListener("load",()=>navigator.serviceWorker.register("./sw.js").catch(console.error));
}

init().catch(e=>{console.error(e);msg.textContent="Не удалось инициализировать DualVault."});