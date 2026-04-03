const tabs=document.querySelectorAll(".tab");
const panels=document.querySelectorAll(".panel");

tabs.forEach(tab=>{
tab.onclick=()=>{
tabs.forEach(t=>t.classList.remove("active"));
panels.forEach(p=>p.classList.remove("active"));

tab.classList.add("active");
document.getElementById(tab.dataset.tab).classList.add("active");
};
});


const video=document.getElementById("video");
const canvas=document.getElementById("canvas");
const ctx=canvas.getContext("2d");

let scanning=false;

document.getElementById("startCamera").onclick=async()=>{

const stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}});
video.srcObject=stream;
scanning=true;
scanFrame();

};

function scanFrame(){

if(!scanning) return;

canvas.width=video.videoWidth;
canvas.height=video.videoHeight;

ctx.drawImage(video,0,0);

const img=ctx.getImageData(0,0,canvas.width,canvas.height);

const code=jsQR(img.data,img.width,img.height);

if(code){

document.getElementById("cameraResult").innerText=code.data;

scanUrl(code.data);

scanning=false;

return;

}

requestAnimationFrame(scanFrame);

}



document.getElementById("fileInput").addEventListener("change",function(){

const file=this.files[0];

const reader=new FileReader();

reader.onload=function(){

const img=new Image();

img.onload=function(){

canvas.width=img.width;
canvas.height=img.height;

ctx.drawImage(img,0,0);

const imgData=ctx.getImageData(0,0,canvas.width,canvas.height);

const code=jsQR(imgData.data,canvas.width,canvas.height);

if(code){

document.getElementById("fileResult").innerText=code.data;

scanUrl(code.data);

}

else{

alert("QR not found");

}

};

img.src=reader.result;

};

reader.readAsDataURL(file);

});



document.getElementById("scanBtn").onclick=()=>{

const url=document.getElementById("urlInput").value;

scanUrl(url);

};



async function scanUrl(url){

const res=await fetch("/api/v1/check-url",{

method:"POST",

headers:{"Content-Type":"application/json"},

body:JSON.stringify({url:url})

});

const data=await res.json();

showResults(data);

}



function showResults(data){

document.getElementById("results").style.display="block";

document.getElementById("statusText").innerText=data.status;

document.getElementById("riskScore").innerText="Risk Score: "+data.risk_score+"%";

document.getElementById("scoreFill").style.width=data.risk_score+"%";

const list=document.getElementById("reasons");

list.innerHTML="";

data.reasons.forEach(r=>{

const li=document.createElement("li");
li.textContent=r;
list.appendChild(li);

});

document.getElementById("advice").innerText=data.advice;

}