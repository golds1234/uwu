// @ts-ignore
import { connect } from 'cloudflare:sockets';

// Configuration Constants
const CONFIG = {
  USER_ID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  PROXY_IPS: ['www.samsung.com', 'www.adobe.com'],
  DOH_URL: 'https://freedns.controld.com/p0',
  HTTP_PORTS: new Set([80, 8080, 8880, 2052, 2086, 2095, 2082]),
  HTTPS_PORTS: new Set([443, 8443, 2053, 2096, 2087, 2083]),
  WS_READY_STATE: {
    OPEN: 1,
    CLOSING: 2
  },
  ENCODED_STRINGS: {
    AT: 'QA==',
    PT: 'dmxlc3M=',
    ED: 'RUR0dW5uZWw='
  }
};

// Initialize variables with config values
let userID = CONFIG.USER_ID;
let พร็อกซีไอพี = "[2a01:4f8:c2c:123f:64:5:6810:c55a]";
let dohURL = CONFIG.DOH_URL;

// Utility Functions
class Utils {
  static isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }

  static safeCloseWebSocket(socket) {
    try {
      if (socket.readyState === CONFIG.WS_READY_STATE.OPEN || 
          socket.readyState === CONFIG.WS_READY_STATE.CLOSING) {
        socket.close();
      }
    } catch (error) {
      console.error('safeCloseWebSocket error', error);
    }
  }

  static base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    
    try {
      base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
      const decode = atob(base64Str);
      const arryBuffer = Uint8Array.from(decode, c => c.charCodeAt(0));
      return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
      return { earlyData: null, error };
    }
  }

  static stringifyUUID(arr, offset = 0) {
    const byteToHex = [];
    for (let i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).slice(1));
    }

    const unsafeStringify = (arr, offset) => {
      return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + 
              byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + 
              byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + 
              byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + 
              byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + 
              byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + 
              byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + 
              byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
    };

    const uuid = unsafeStringify(arr, offset);
    if (!this.isValidUUID(uuid)) {
      throw TypeError("Stringified UUID is invalid");
    }
    return uuid;
  }
}

// วเลส Protocol Handler
class VLESSHandler {
  static processHeader(vlessBuffer, userID) {
    if (vlessBuffer.byteLength < 24) {
      return { hasError: true, message: 'invalid data' };
    }

    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
    const slicedBufferString = Utils.stringifyUUID(slicedBuffer);
    const uuids = userID.includes(',') ? userID.split(",") : [userID];
    const isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || 
                       (uuids.length === 1 && slicedBufferString === uuids[0].trim());

    if (!isValidUser) {
      return { hasError: true, message: 'invalid user' };
    }

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
    let isUDP = false;

    if (command === 1) {
      isUDP = false;
    } else if (command === 2) {
      isUDP = true;
    } else {
      return {
        hasError: true,
        message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`
      };
    }

    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    switch (addressType) {
      case 1:
        addressLength = 4;
        addressValue = new Uint8Array(
          vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
        ).join('.');
        break;
      case 2:
        addressLength = new Uint8Array(
          vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
        )[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(
          vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
        );
        break;
      case 3:
        addressLength = 16;
        const dataView = new DataView(
          vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
        );
        const ipv6 = [];
        for (let i = 0; i < 8; i++) {
          ipv6.push(dataView.getUint16(i * 2).toString(16));
        }
        addressValue = ipv6.join(':');
        break;
      default:
        return {
          hasError: true,
          message: `invalid addressType ${addressType}`
        };
    }

    if (!addressValue) {
      return {
        hasError: true,
        message: `addressValue is empty, addressType is ${addressType}`
      };
    }

    return {
      hasError: false,
      addressRemote: addressValue,
      addressType,
      portRemote,
      rawDataIndex: addressValueIndex + addressLength,
      vlessVersion: version,
      isUDP
    };
  }
}

// WebSocket Stream Handler
class WebSocketStreamHandler {
  static makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    
    return new ReadableStream({
      start(controller) {
        webSocketServer.addEventListener('message', (event) => {
          controller.enqueue(event.data);
        });

        webSocketServer.addEventListener('close', () => {
          Utils.safeCloseWebSocket(webSocketServer);
          controller.close();
        });

        webSocketServer.addEventListener('error', (err) => {
          log('webSocketServer has error');
          controller.error(err);
        });

        const { earlyData, error } = Utils.base64ToArrayBuffer(earlyDataHeader);
        if (error) controller.error(error);
        else if (earlyData) controller.enqueue(earlyData);
      },
      cancel(reason) {
        log(`ReadableStream was canceled, due to ${reason}`);
        readableStreamCancel = true;
        Utils.safeCloseWebSocket(webSocketServer);
      }
    });
  }
}

// TCP/UDP Connection Handler
class ConnectionHandler {
  static async handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    async function connectAndWrite(address, port) {
      const tcpSocket = connect({ hostname: address, port });
      remoteSocket.value = tcpSocket;
      log(`connected to ${address}:${port}`);
      
      const writer = tcpSocket.writable.getWriter();
      await writer.write(rawClientData);
      writer.releaseLock();
      return tcpSocket;
    }

    async function retry() {
      const tcpSocket = await connectAndWrite(พร็อกซีไอพี || addressRemote, portRemote);
      tcpSocket.closed.catch(error => {
        console.log('retry tcpSocket closed error', error);
      }).finally(() => {
        Utils.safeCloseWebSocket(webSocket);
      });
      this.remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    this.remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
  }

  static async handleUDPOutBound(webSocket, vlessResponseHeader, log) {
    let isVlessHeaderSent = false;
    
    const transformStream = new TransformStream({
      transform(chunk, controller) {
        for (let index = 0; index < chunk.byteLength;) {
          const lengthBuffer = chunk.slice(index, index + 2);
          const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
          const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
          index = index + 2 + udpPakcetLength;
          controller.enqueue(udpData);
        }
      }
    });

    transformStream.readable.pipeTo(new WritableStream({
      async write(chunk) {
        const resp = await fetch(dohURL, {
          method: 'POST',
          headers: { 'content-type': 'application/dns-message' },
          body: chunk,
        });
        
        const dnsQueryResult = await resp.arrayBuffer();
        const udpSize = dnsQueryResult.byteLength;
        const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
        
        if (webSocket.readyState === CONFIG.WS_READY_STATE.OPEN) {
          log(`doh success and dns message length is ${udpSize}`);
          const dataToSend = isVlessHeaderSent 
            ? await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer()
            : await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
          
          webSocket.send(dataToSend);
          isVlessHeaderSent = true;
        }
      }
    })).catch(error => log('dns udp has error' + error));

    const writer = transformStream.writable.getWriter();
    return { write: chunk => writer.write(chunk) };
  }

  static async remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
    let remoteChunkCount = 0;
    let hasIncomingData = false;
    let vlessHeader = vlessResponseHeader;

    await remoteSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        hasIncomingData = true;
        remoteChunkCount++;
        
        if (webSocket.readyState !== CONFIG.WS_READY_STATE.OPEN) {
          throw new Error('webSocket.readyState is not open, maybe close');
        }

        if (vlessHeader) {
          webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
          vlessHeader = null;
        } else {
          webSocket.send(chunk);
        }
      },
      close() {
        log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
      },
      abort(reason) {
        console.error(`remoteConnection!.readable abort`, reason);
      },
    })).catch(error => {
      console.error(`remoteSocketToWS has exception`, error.stack || error);
      Utils.safeCloseWebSocket(webSocket);
    });

    if (!hasIncomingData && retry) {
      log(`retrying connection`);
      retry();
    }
  }
}

// Configuration Generator
class ConfigGenerator {
  static getVlessConfig(userIDs, hostName) {
    const commonUrlPart = `:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
    const hashSeparator = "################################################################";
    const userIDArray = userIDs.split(",");

    const output = userIDArray.map(userID => {
      const vlessMain = `${atob(CONFIG.ENCODED_STRINGS.PT)}://${userID}${atob(CONFIG.ENCODED_STRINGS.AT)}${hostName}${commonUrlPart}`;
      const vlessSec = `${atob(CONFIG.ENCODED_STRINGS.PT)}://${userID}${atob(CONFIG.ENCODED_STRINGS.AT)}${พร็อกซีไอพี}${commonUrlPart}`;
      
      return `<h2>UUID: ${userID}</h2>${hashSeparator}
v2ray default ip
---------------------------------------------------------------
${vlessMain}
<button onclick='copyToClipboard("${vlessMain}")'><i class="fa fa-clipboard"></i> Copy vlessMain</button>
---------------------------------------------------------------
v2ray with bestip
---------------------------------------------------------------
${vlessSec}
<button onclick='copyToClipboard("${vlessSec}")'><i class="fa fa-clipboard"></i> Copy vlessSec</button>
---------------------------------------------------------------`;
    }).join('\n');

    const sublink = `https://${hostName}/sub/${userIDArray[0]}`;
    const subbestip = `https://${hostName}/bestip/${userIDArray[0]}`;
    const clash_link = `https://api.v1.mk/sub?target=clash&url=${encodeURIComponent(sublink)}&insert=false&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;

    const header = `
<p align='center'><img src='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' alt='EDtunnel' style='margin-bottom: -50px;'>
<b style='font-size: 15px;'>Welcome! This function generates configuration for VLESS protocol.</b>
<b style='font-size: 15px;'>欢迎！这是生成 VLESS 协议的配置。</b>
<a href='https://github.com/3Kmfi6HP/EDtunnel' target='_blank'>EDtunnel - https://github.com/3Kmfi6HP/EDtunnel</a>
<iframe src='https://ghbtns.com/github-btn.html?user=3Kmfi6HP&repo=EDtunnel&type=star&count=true&size=large' frameborder='0' scrolling='0' width='170' height='30' title='GitHub'></iframe>
<a href='//${hostName}/sub/${userIDArray[0]}' target='_blank'>VLESS 节点订阅连接</a>
<a href='clash://install-config?url=${encodeURIComponent(`https://${hostName}/sub/${userIDArray[0]}?format=clash`)}' target='_blank'>Clash for Windows 节点订阅连接</a>
<a href='${clash_link}' target='_blank'>Clash 节点订阅连接</a>
<a href='${subbestip}' target='_blank'>优选IP自动节点订阅</a>
<a href='clash://install-config?url=${encodeURIComponent(subbestip)}' target='_blank'>Clash优选IP自动</a>
<a href='sing-box://import-remote-profile?url=${encodeURIComponent(subbestip)}' target='_blank'>singbox优选IP自动</a>
<a href='sn://subscription?url=${encodeURIComponent(subbestip)}' target='_blank'>nekobox优选IP自动</a>
<a href='v2rayng://install-config?url=${encodeURIComponent(subbestip)}' target='_blank'>v2rayNG优选IP自动</a></p>`;

    const htmlHead = `
<head>
  <title>EDtunnel: VLESS configuration</title>
  <meta name='description' content='VLESS protocol configuration generator'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <meta property='og:title' content='EDtunnel - VLESS configuration' />
  <meta property='og:description' content='VLESS protocol configuration generator' />
  <meta property='og:url' content='https://${hostName}/' />
  <meta property='og:image' content='https://api.qrserver.com/v1/create-qr-code/?size=500x500&data=${encodeURIComponent(`vless://${userIDs.split(",")[0]}@${hostName}${commonUrlPart}`)}' />
  <meta name='twitter:card' content='summary_large_image' />

  <style>
    body { font-family: Arial, sans-serif; background-color: #f0f0f0; color: #333; padding: 10px; }
    a { color: #1a0dab; text-decoration: none; }
    img { max-width: 100%; height: auto; }
    pre { white-space: pre-wrap; word-wrap: break-word; background-color: #fff; border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
    @media (prefers-color-scheme: dark) {
      body { background-color: #333; color: #f0f0f0; }
      a { color: #9db4ff; }
      pre { background-color: #282a36; border-color: #6272a4; }
    }
  </style>
  <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css'>
</head>`;

    return `
<html>
${htmlHead}
<body>
<pre style='background-color: transparent; border: none;'>${header}</pre>
<pre>${output}</pre>
</body>
<script>
  function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
      .then(() => alert("Copied to clipboard"))
      .catch(err => console.error("Failed to copy:", err));
  }
</script>
</html>`;
  }

  static createVlessSub(userIDPath, hostName) {
    const userIDArray = userIDPath.includes(',') ? userIDPath.split(',') : [userIDPath];
    const commonUrlPartHttp = `?encryption=none&security=none&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`;
    const commonUrlPartHttps = `?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`;

    const result = userIDArray.flatMap(userID => {
      const httpConfig = Array.from(CONFIG.HTTP_PORTS).flatMap(port => {
        if (!hostName.includes('pages.dev')) {
          const urlPart = `${hostName}-HTTP-${port}`;
          const vlessMainHttp = `${atob(CONFIG.ENCODED_STRINGS.PT)}://${userID}${atob(CONFIG.ENCODED_STRINGS.AT)}${hostName}:${port}${commonUrlPartHttp}${urlPart}`;
          return CONFIG.PROXY_IPS.flatMap(proxyIP => {
            const vlessSecHttp = `${atob(CONFIG.ENCODED_STRINGS.PT)}://${userID}${atob(CONFIG.ENCODED_STRINGS.AT)}${proxyIP}:${port}${commonUrlPartHttp}${urlPart}-${proxyIP}-${atob(CONFIG.ENCODED_STRINGS.ED)}`;
            return [vlessMainHttp, vlessSecHttp];
          });
        }
        return [];
      });

      const httpsConfig = Array.from(CONFIG.HTTPS_PORTS).flatMap(port => {
        const urlPart = `${hostName}-HTTPS-${port}`;
        const vlessMainHttps = `${atob(CONFIG.ENCODED_STRINGS.PT)}://${userID}${atob(CONFIG.ENCODED_STRINGS.AT)}${hostName}:${port}${commonUrlPartHttps}${urlPart}`;
        return CONFIG.PROXY_IPS.flatMap(proxyIP => {
          const vlessSecHttps = `${atob(CONFIG.ENCODED_STRINGS.PT)}://${userID}${atob(CONFIG.ENCODED_STRINGS.AT)}${proxyIP}:${port}${commonUrlPartHttps}${urlPart}-${proxyIP}-${atob(CONFIG.ENCODED_STRINGS.ED)}`;
          return [vlessMainHttps, vlessSecHttps];
        });
      });

      return [...httpConfig, ...httpsConfig];
    });

    return result.join('\n');
  }
}

// Main Worker Class
export default {
  async fetch(request, env, ctx) {
    try {
      // Update configuration from environment variables
      userID = env.UUID || userID;
      พร็อกซีไอพี = env.พร็อกซีไอพี || พร็อกซีไอพี;
      dohURL = env.DNS_RESOLVER_URL || dohURL;
      
      const userID_Path = userID.includes(',') ? userID.split(',')[0] : userID;
      const upgradeHeader = request.headers.get('Upgrade');
      
      if (!upgradeHeader || upgradeHeader !== 'websocket') {
        const url = new URL(request.url);
        
        switch (url.pathname) {
          case `/cf`:
            return new Response(JSON.stringify(request.cf, null, 4), {
              headers: { "Content-Type": "application/json;charset=utf-8" }
            });
            
          case `/${userID_Path}`:
            return new Response(ConfigGenerator.getVlessConfig(userID, request.headers.get('Host')), {
              headers: { "Content-Type": "text/html; charset=utf-8" }
            });
            
          case `/sub/${userID_Path}`:
            return new Response(btoa(ConfigGenerator.createVlessSub(userID, request.headers.get('Host'))), {
              headers: { "Content-Type": "text/plain;charset=utf-8" }
            });
            
          case `/bestip/${userID_Path}`:
            return fetch(`https://sub.xf.free.hr/auto?host=${request.headers.get('Host')}&uuid=${userID}&path=/`, {
              headers: request.headers
            });
            
          default:
            return this.handleReverseProxy(request, url);
        }
      } else {
        return this.handleWebSocket(request);
      }
    } catch (err) {
      return new Response(err.toString());
    }
  },

  async handleReverseProxy(request, url) {
    const randomHostname = [
      'cdn.appsflyer.com',
      // Add more domains as needed
    ][Math.floor(Math.random() * 1)]; // Adjust based on array length
    
    const newHeaders = new Headers(request.headers);
    newHeaders.set('cf-connecting-ip', '1.2.3.4');
    newHeaders.set('x-forwarded-for', '1.2.3.4');
    newHeaders.set('x-real-ip', '1.2.3.4');
    newHeaders.set('referer', 'https://www.google.com/search?q=edtunnel');
    
    const proxyUrl = 'https://' + randomHostname + url.pathname + url.search;
    const modifiedRequest = new Request(proxyUrl, {
      method: request.method,
      headers: newHeaders,
      body: request.body,
      redirect: 'manual',
    });
    
    const proxyResponse = await fetch(modifiedRequest, { redirect: 'manual' });
    
    if ([301, 302].includes(proxyResponse.status)) {
      return new Response(`Redirects to ${randomHostname} are not allowed.`, {
        status: 403,
        statusText: 'Forbidden',
      });
    }
    
    return proxyResponse;
  },

  async handleWebSocket(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const currentDate = new Date();
    const log = (info, event) => {
      console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
    };

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = WebSocketStreamHandler.makeReadableWebSocketStream(
      webSocket, earlyDataHeader, log
    );

    let remoteSocketWapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;

    await readableWebSocketStream.pipeTo(new WritableStream({
      async write(chunk) {
        if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
        if (remoteSocketWapper.value) {
          const writer = remoteSocketWapper.value.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }

        const {
          hasError,
          message,
          portRemote = 443,
          addressRemote = '',
          rawDataIndex,
          vlessVersion = new Uint8Array([0, 0]),
          isUDP,
        } = VLESSHandler.processHeader(chunk, userID);

        address = addressRemote;
        portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
        
        if (hasError) throw new Error(message);
        if (isUDP && portRemote !== 53) {
          throw new Error('UDP proxy only enabled for DNS which is port 53');
        }

        isDns = isUDP && portRemote === 53;
        const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
        const rawClientData = chunk.slice(rawDataIndex);

        if (isDns) {
          const { write } = await ConnectionHandler.handleUDPOutBound(
            webSocket, vlessResponseHeader, log
          );
          udpStreamWrite = write;
          udpStreamWrite(rawClientData);
        } else {
          await ConnectionHandler.handleTCPOutBound(
            remoteSocketWapper, addressRemote, portRemote, 
            rawClientData, webSocket, vlessResponseHeader, log
          );
        }
      },
      close() { log(`readableWebSocketStream is close`); },
      abort(reason) { log(`readableWebSocketStream is abort`, JSON.stringify(reason)); },
    })).catch(err => log('readableWebSocketStream pipeTo error', err));

    return new Response(null, { status: 101, webSocket: client });
  }
};
