const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require("../config/mysql");
/**
 * Genera una firma electrónica (sello) a partir de una cadena y una llave privada.
 * @param {string} cadenaOrigen - Los datos que se van a firmar.
 * @param {string} privateKeyPem - La llave privada en formato PEM.
 * @returns {string} - La firma electrónica resultante en Base64.
 */
const firmar_cadena = (cadena, llave) => {
    // 1. Crear el objeto de firma usando el algoritmo deseado
    const sign = crypto.createSign('SHA256');

    // 2. Cargar la cadena de origen
    sign.update(cadena);
    sign.end();

    // 3. Firmar con la llave privada y devolver en Base64
    const signature = sign.sign(llave, 'base64');
    
    return signature;
}

const firmar_cadena_llave = (cadena, llave, pass) => {
    const signature = crypto.sign(
        "sha256",
        Buffer.from(cadena),
        {
            key: llave,
            passphrase: pass,
            format: 'der',
            type: 'pkcs8'
        }
    );

    return signature.toString('base64');
}

const firma_individual = async (req, res) => {
    const { cadena, idx, password, doc_tipo, owner_nombre, owner_apellidos, owner_curp, sign_nombre, sign_apellidos, sign_emisor } = req.body;

    const con = await db.getConnection();

    try{
        const llavePrivada = req.files['llave'][0].buffer;
        const certificado = req.files['certificado'][0].buffer;
    
        //Validacion de emisor
        const cert = new crypto.X509Certificate(certificado);
        const match = cert.issuer.match(/O=([^\n,]+)/);
        const organizacion = match ? match[1].trim() : "No encontrada";
        console.log(organizacion);

        if(organizacion === 'Gobierno del Estado de Jalisco' && sign_emisor !== 'GOB DE JALISCO'){
            return res.status(200).json({
                ok: false,
                msg: 'Emisor incorrecto'
            });
        }

        if(organizacion === 'SERVICIO DE ADMINISTRACION TRIBUTARIA' && sign_emisor !== 'SAT'){
            return res.status(200).json({
                ok: false,
                msg: 'Emisor incorrecto'
            });
        }
        
        const sello = firmar_cadena_llave(cadena, llavePrivada, password);
        const id = uuidv4();
        const obj = [id, idx, doc_tipo, owner_nombre, owner_apellidos, owner_curp, sign_nombre, sign_apellidos, sign_emisor, cadena, sello];
        console.log(obj);

        await con.query("INSERT INTO validaciones(doc_uuid, doc_idx, doc_tipo, doc_date, owner_nombre, owner_apellidos, owner_curp, sign_nombre, sign_apellidos, sign_emisor, doc_cadena, doc_sello)"+
            " VALUES (?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?)", obj
        );

        res.status(200).json({
            ok: true,
            idx,
            id,
            sign_emisor,
            cadenaOrigen: cadena,
            sello: sello
        });

    }catch(err){
        console.log(err);
        res.status(400).json({
            ok: false,
            msg: "firma no valida"
        });
    }finally{
        con.release();
    }
    
}

const firma_multiple = async (req, res) => {
    const {password, sign_emisor} = req.body;

    const con = await db.getConnection();

    try{
        //const llavePrivada = req.file.buffer;
        const llavePrivada = req.files['llave'][0].buffer;
        const certificado = req.files['certificado'][0].buffer;

        //Validacion de emisor
        const cert = new crypto.X509Certificate(certificado);
        const match = cert.issuer.match(/O=([^\n,]+)/);
        const organizacion = match ? match[1].trim() : "No encontrada";
        console.log(organizacion);

        if(organizacion === 'Gobierno del Estado de Jalisco' && sign_emisor !== 'GOB DE JALISCO'){
            return res.status(200).json({
                ok: false,
                msg: 'Emisor incorrecto'
            });
        }

        if(organizacion === 'SERVICIO DE ADMINISTRACION TRIBUTARIA' && sign_emisor !== 'SAT'){
            return res.status(200).json({
                ok: false,
                msg: 'Emisor incorrecto'
            });
        }

        const obj_final = [];

        const informacion = JSON.parse(req.body.informacion);
        
        for(info of informacion){
            const sello = firmar_cadena_llave(info.cadena, llavePrivada, password);
            
            const id = uuidv4();
            const obj = [id, info.doc_idx, info.doc_tipo, info.owner_nombre, info.owner_apellidos, info.owner_curp, info.sign_nombre, info.sign_apellidos, sign_emisor, info.cadena, sello];

            const objeto_individual = {
                id,
                idx: info.doc_idx,
                sign_emisor: sign_emisor,
                cadenaOrigen: info.cadena,
                sello
            }

            await con.query("INSERT INTO validaciones(doc_uuid, doc_idx, doc_tipo, doc_date, owner_nombre, owner_apellidos, owner_curp, sign_nombre, sign_apellidos, sign_emisor, doc_cadena, doc_sello)"+
                " VALUES (?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?)", obj
            );

            obj_final.push(objeto_individual);
        }

        res.status(200).json({ok: true, data: obj_final});
       //res.status(200).json({ok: true});

    }catch(err){
        console.log(err);
        res.status(400).json({
            ok: false,
            msg: "firma no valida"
        });
    }finally{
        con.release();
    }

}

module.exports = {
    firma_individual,
    firma_multiple
}