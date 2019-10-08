const raw = require('raw-socket') // npm install raw-socket

// raw icmp ping data, copy/pasted from wireshark
const pingPayload = Buffer.from(
 [
   '08004352', // icmp header
   '00010a09',
   '61626364', // payload (abcdef...)
   '65666768',
   '696a6b6c',
   '6d6e6f70',
   '71727374',
   '75767761',
   '62636465',
   '66676869',
 ].join(''),
 'hex'
)

const ping = (dest, { ttl, maxWait }) =>
 new Promise((resolve, reject) => {
   const socket = raw.createSocket({ protocol: raw.Protocol.ICMP })
   socket.send(
     pingPayload,
     0,
     pingPayload.length,
     dest,
     () => {
       socket.setOption(
         raw.SocketLevel.IPPROTO_IP,
         raw.SocketOption.IP_TTL,
         ttl
       )
     },
     err => {
       if (err) reject(err)
     }
   )
   const timeout = setTimeout(() => {
     reject(err('timeout'))
   }, maxWait * 1e3)
   socket.on('message', function (payload, addr) {
     clearTimeout(timeout)
     socket.close()
     resolve({ payload, addr })
   })
 })

const err = (type, msg) => {
 let e = new Error(msg || type)
 Error.captureStackTrace(e, err)
 e[type] = true
 return e
}

// run
;(async () => {
 const target = process.argv[2] || '216.58.195.238'
 const maxHops = 64
 const maxWait = 5

 for (let ttl = 1; ttl <= maxHops; ttl++) {
   try {
     const { addr } = await ping(target, { ttl, maxWait })
     console.log(addr)
     if (addr === target) process.exit()
   } catch (err) {
     if (err.timeout) console.log('*')
     else {
       console.error(err.stack)
       process.abort()
     }
   }
 }
})()
