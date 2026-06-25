const qrInput = document.getElementById("qrInput");
const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");

const resultado = document.getElementById("resultado");
const urlDetectada = document.getElementById("urlDetectada");
const diagnostico = document.getElementById("diagnostico");
const abrirBtn = document.getElementById("abrirBtn");

let urlFinal = "";

function escaparHTML(str) {
    return str.replace(/[&<>"']/g, function(m) {
        const mapeo = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return mapeo[m];
    });
}

qrInput.addEventListener("change", function(event) {
    const archivo = event.target.files[0];

    if (!archivo) {
        return;
    }

    const lector = new FileReader();

    lector.onload = function() {
        const imagen = new Image();

        imagen.onload = function() {
            canvas.width = imagen.width;
            canvas.height = imagen.height;

            ctx.drawImage(imagen, 0, 0);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

            const qr = jsQR(
                imageData.data,
                imageData.width,
                imageData.height
            );

            if (qr) {
                analizarContenido(qr.data);
            } else {
                diagnostico.innerHTML = `<h3 class="malicioso">No se detecto ningun codigo QR en la imagen.</h3>`;
                abrirBtn.style.display = "none";
            }
        };

        imagen.src = lector.result;
    };

    lector.readAsDataURL(archivo);
});

function analizarContenido(contenido) {
    resultado.classList.remove("oculto");
    abrirBtn.style.display = "inline-block";
    urlDetectada.textContent = contenido;

    let riesgo = 0;
    let reporte = "";
    let cadenaAnalizar = contenido.trim();

    if (!/^https?:\/\//i.test(cadenaAnalizar) && /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}/i.test(cadenaAnalizar)) {
        cadenaAnalizar = "https://" + cadenaAnalizar;
    }

    try {
        const url = new URL(cadenaAnalizar);
        urlFinal = url.href;

        const protocoloEscapado = escaparHTML(url.protocol);
        const dominioEscapado = escaparHTML(url.hostname);
        const rutaEscapada = escaparHTML(url.pathname);

        reporte += `
            <p><strong>Protocolo:</strong> ${protocoloEscapado}</p>
            <p><strong>Dominio:</strong> ${dominioEscapado}</p>
            <p><strong>Ruta:</strong> ${rutaEscapada}</p>
        `;

        if (url.protocol === "http:") {
            riesgo += 2;
            reporte += `<p class="advertencia">Advertencia: La URL utiliza HTTP en lugar de HTTPS.</p>`;
        }

        const acortadores = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", 
            "shorturl.at", "cutt.ly", "ow.ly"
        ];

        if (acortadores.includes(url.hostname.toLowerCase())) {
            riesgo += 2;
            reporte += `<p class="advertencia">Advertencia: Se detecto un servicio de acortamiento de enlaces.</p>`;
        }

        const dominiosSospechosos = ["g00gle", "faceb00k", "paypa1", "amaz0n", "micr0soft"];
        dominiosSospechosos.forEach(dominio => {
            if (url.hostname.toLowerCase().includes(dominio)) {
                riesgo += 3;
                reporte += `<p class="advertencia">Advertencia: Posible intento de suplantacion mediante typosquatting.</p>`;
            }
        });

        const cantidadParametros = (url.search.match(/&/g) || []).length;
        if (cantidadParametros > 5) {
            riesgo += 1;
            reporte += `<p class="advertencia">La URL contiene una cantidad inusual de variables de seguimiento.</p>`;
        }

        const palabrasRiesgo = [
            "casino", "bet", "bonus", "bono", "apuesta", 
            "apuestas", "gambling", "promo", "promocion"
        ];

        let palabraEncontrada = false;
        palabrasRiesgo.forEach(palabra => {
            if (url.href.toLowerCase().includes(palabra) && !palabraEncontrada) {
                riesgo += 1;
                palabraEncontrada = true;
                reporte += `<p class="advertencia">Se detecto contenido asociado a promociones o apuestas.</p>`;
            }
        });

        const palabrasPhishing = ["login", "signin", "verify", "verification", "soporte", "cuenta", "banco", "secure-login"];
        let phishingEncontrado = false;
        palabrasPhishing.forEach(palabra => {
            if (url.href.toLowerCase().includes(palabra) && !phishingEncontrado) {
                riesgo += 2.5;
                phishingEncontrado = true;
                reporte += `<p class="advertencia">Advertencia: La URL solicita acciones de inicio de sesion o verificacion sospechosas.</p>`;
            }
        });

        if (/\d{4,}/.test(url.hostname)) {
            riesgo += 2;
            reporte += `<p class="advertencia">Advertencia: El dominio contiene patrones numericos sospechosos.</p>`;
        }

        const partesDominio = url.hostname.split('.');
        if (partesDominio.length > 3) {
            riesgo += 1.5;
            reporte += `<p class="advertencia">Advertencia: Estructura de subdominios inusualmente compleja.</p>`;
        }

        const tldsSospechosos = [".online", ".top", ".xyz", ".click", ".download", ".info", ".biz", ".cc"];
        let tldEncontrado = false;
        tldsSospechosos.forEach(tld => {
            if (url.hostname.toLowerCase().endsWith(tld) && !tldEncontrado) {
                riesgo += 2;
                tldEncontrado = true;
                reporte += `<p class="advertencia">Advertencia: El dominio utiliza una extension (TLD) frecuentemente usada para campanas maliciosas.</p>`;
            }
        });

        const trackersPublicitarios = ["adcash", "clickunder", "popunder", "adnetwork", "revenuehit"];
        let trackerEncontrado = false;
        trackersPublicitarios.forEach(tracker => {
            if (url.href.toLowerCase().includes(tracker) && !trackerEncontrado) {
                riesgo += 1.5;
                trackerEncontrado = true;
                reporte += `<p class="advertencia">Advertencia: Se detectaron parametros asociados a redes de anuncios agresivas.</p>`;
            }
        });

        let nivel = "";
        let clase = "";

        if (riesgo <= 1) {
            nivel = "Seguro";
            clase = "seguro";
        } else if (riesgo <= 3) {
            nivel = "Sospechoso";
            clase = "sospechoso";
        } else {
            nivel = "Malicioso";
            clase = "malicioso";
        }

        reporte += `
            <h3 class="${clase}">
                Nivel de riesgo: ${nivel} (Puntos: ${riesgo})
            </h3>
        `;

        diagnostico.innerHTML = reporte;

    } catch (error) {
        diagnostico.innerHTML = `
            <h3 class="malicioso">
                El contenido del codigo QR no corresponde a una URL valida.
            </h3>
        `;
        abrirBtn.style.display = "none";
    }
}

abrirBtn.addEventListener("click", function() {
    window.open(urlFinal, "_blank");
});