const API = "/api/v1/check-url"



function openTab(id){

document.querySelectorAll(".tabcontent").forEach(e=>e.classList.remove("active"))

document.getElementById(id).classList.add("active")

}



async function sendToBackend(url){

document.getElementById("output").innerText="Scanning..."

try{

let res = await fetch(API,{

method:"POST",

headers:{

"Content-Type":"application/json"

},

body:JSON.stringify({url:url})

})

let data = await res.json()

displayResult(data)

}

catch(e){

document.getElementById("output").innerText="Server error"

}

}



function displayResult(data){

let text="URL: "+data.url+"\n\n"

text+="Status: "+data.status+"\n"

text+="Risk Score: "+data.risk_percent+"\n\n"

text+="Advice: "+data.advice+"\n\n"

text+="Reasons:\n"

data.reasons.forEach(r=>{

text+="• "+r+"\n"

})

document.getElementById("output").innerText=text

}



function scanURL(){

let url=document.getElementById("urlText").value

if(!url) return

sendToBackend(url)

}



// CAMERA SCANNER

function onScanSuccess(decodedText){

sendToBackend(decodedText)

}

const scanner=new Html5QrcodeScanner(

"reader",

{fps:10,qrbox:250}

)

scanner.render(onScanSuccess)



// FILE QR

document.getElementById("fileInput").addEventListener("change",function(e){

const file=e.target.files[0]

const img=new Image()

const canvas=document.getElementById("canvas")

const ctx=canvas.getContext("2d")

img.onload=function(){

canvas.width=img.width

canvas.height=img.height

ctx.drawImage(img,0,0)

const imageData=ctx.getImageData(0,0,canvas.width,canvas.height)

const code=jsQR(imageData.data,imageData.width,imageData.height)

if(code){

sendToBackend(code.data)

}

else{

alert("QR not detected")

}

}

img.src=URL.createObjectURL(file)

})