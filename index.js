import jws from 'jws'
import crypto, { sign } from 'crypto'
import { Readable } from 'stream'
import fs from 'fs'
import _ from 'lodash'

const base64UrlEncode = str => {
  return Buffer.from(JSON.stringify(str)).toString('base64url')
}

// simulate jws.sign
const payload = {
  message: 'Hello world',
}
const header = {
  alg: 'HS512', // HS256, HS384, HS512
}
const secretKey = 'secret'
const signature = jws.sign({
  header,
  payload,
  secret: secretKey,
})
const signaturePaths = signature.split('.')
const jwsHeader = base64UrlEncode(header)
const jwsPayload = base64UrlEncode(payload)
const messageupdate = `${jwsHeader}.${jwsPayload}`
const jwsSignature = crypto
  .createHmac('sha512', secretKey)
  .update(messageupdate)
  .digest('base64url')
console.log(signaturePaths[0] === jwsHeader)
console.log(signaturePaths[1] === jwsPayload)
console.log(signaturePaths[2] === jwsSignature)

// simulate jws.verify
jws.verify(signature, 'HS512', secretKey)
// simulate jws.decode
const jwsDecode = jws.decode(signature)
const headerDecode = JSON.parse(
  Buffer.from(signaturePaths[0], 'base64url').toString()
)
const payloadDecode = Buffer.from(signaturePaths[1], 'base64url').toString()

console.log(
  _.isEqual(jwsDecode, {
    header: headerDecode,
    payload: payloadDecode,
    signature: signaturePaths[2],
  })
)

// simulate jws.createSign
const headerRs256 = {
  alg: 'RS256',
}
const payloadRs256 = {
  message: 'Hello world',
}
const jwsHeaderRs256 = Buffer.from(JSON.stringify(headerRs256)).toString(
  'base64url'
)
const jwsPayloadRs256 = Buffer.from(JSON.stringify(payloadRs256)).toString(
  'base64url'
)
const messageUpdateRs256 = `${jwsHeaderRs256}.${jwsPayloadRs256}`
const privateKey = fs.readFileSync(process.cwd() + '/private-key.pem', 'utf8')
// Tạo một đối tượng chữ ký số sử dụng thuật toán RSA-SHA256
const signer = crypto
  .createSign('RSA-SHA256')
  .update(messageUpdateRs256)
  .sign(privateKey, 'base64url')
// createSign() tạo ra một instance của Readable stream
const jwsCreateSign = jws.createSign({
  header: headerRs256,
})
Readable.from(privateKey).pipe(jwsCreateSign.privateKey)
Readable.from(JSON.stringify(payloadRs256)).pipe(jwsCreateSign.payload)
const signatureStream = await new Promise(resolve => {
  jwsCreateSign.on('done', function (signature) {
    resolve(signature)
  })
})

console.log(signatureStream.split('.')[2] === signer)

// simulate jws.createVerify
const publicKey = fs.readFileSync(process.cwd() + '/public-key.pem', 'utf8')
const verify = crypto
  .createVerify('RSA-SHA256')
  .update(messageUpdateRs256)
  .verify(publicKey, signatureStream.split('.')[2], 'base64url')
console.log('verify', verify)
