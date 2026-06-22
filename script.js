const qrInput = document.getElementById("qrInput");
const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");

const resultado = document.getElementById("resultado");
const urlDetectada = document.getElementById("urlDetectada");
const diagnostico = document.getElementById("diagnostico");
const abrirBtn = document.getElementById("abrirBtn");

let urlFinal = ""; 
qrInput.addEventListener("change", function(event){

    const archivo = event.target.files[0];

    if(!archivo){
        return;
    }

    const lector = new FileReader();

    lector.onload = function(){

        const imagen = new Image();

        imagen.onload = function(){

            canvas.width = imagen.width;
            canvas.height = imagen.height;

            ctx.drawImage(imagen, 0, 0);

            const imageData = ctx.getImageData(
                0,
                0,
                canvas.width,
                canvas.height
            );

            const qr = jsQR(
                imageData.data,
                imageData.width,
                imageData.height
            );

            if(qr){
                analizarContenido(qr.data);
            }else{
                alert("No se detectó ningún código QR en la imagen.");
            }

        };

        imagen.src = lector.result;
    };

    lector.readAsDataURL(archivo);

});
function analizarContenido(contenido){

    resultado.classList.remove("oculto");
    abrirBtn.style.display = "inline-block";

    urlDetectada.textContent = contenido;

    let riesgo = 0;
    let reporte = "";

    try{

        const url = new URL(contenido);

        urlFinal = contenido;

        reporte += `
            <p><strong>Protocolo:</strong> ${url.protocol}</p>
            <p><strong>Dominio:</strong> ${url.hostname}</p>
            <p><strong>Ruta:</strong> ${url.pathname}</p>
        `; 
