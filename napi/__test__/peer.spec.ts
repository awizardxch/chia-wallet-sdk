import test from "ava";
import { createHash } from "node:crypto";
import { createServer, Server } from "node:https";
import { AddressInfo } from "node:net";
import { Duplex } from "node:stream";

import {
  Certificate,
  Connector,
  Peer,
  PeerOptions,
  Signature,
  SpendBundle,
} from "../index.js";

const NETWORK_ID = "mocknet";

const HANDSHAKE = 1;
const SEND_TRANSACTION = 48;
const TRANSACTION_ACK = 49;
const NEW_PEAK_WALLET = 50;
const REQUEST_CHILDREN = 74;
const RESPOND_CHILDREN = 75;

const u8 = (value: number) => Buffer.from([value]);

const u16 = (value: number) => {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value);
  return buffer;
};

const u32 = (value: number) => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
};

const str = (value: string) => {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32(bytes.length), bytes]);
};

function encodeMessage(type: number, id: number | null, data: Buffer) {
  return Buffer.concat([
    u8(type),
    id === null ? u8(0) : Buffer.concat([u8(1), u16(id)]),
    u32(data.length),
    data,
  ]);
}

function decodeMessage(payload: Buffer) {
  const type = payload[0];
  const id = payload[1] === 1 ? payload.readUInt16BE(2) : null;
  return { type, id };
}

function encodeFrame(opcode: number, payload: Buffer) {
  let header: Buffer;
  if (payload.length < 126) {
    header = Buffer.from([0x80 | opcode, payload.length]);
  } else if (payload.length < 65536) {
    header = Buffer.concat([Buffer.from([0x80 | opcode, 126]), u16(payload.length)]);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  return Buffer.concat([header, payload]);
}

const handshake = () =>
  Buffer.concat([
    str(NETWORK_ID),
    str("0.0.37"),
    str("0.0.0"),
    u16(8444),
    u8(1), // NodeType::FullNode
    u32(0),
  ]);

const newPeakWallet = (height: number) =>
  Buffer.concat([
    Buffer.alloc(32, height),
    u32(height),
    Buffer.alloc(16),
    u32(height),
  ]);

const respondChildren = (amount: number) => {
  const amountBytes = Buffer.alloc(8);
  amountBytes.writeBigUInt64BE(BigInt(amount));
  return Buffer.concat([
    u32(1),
    Buffer.alloc(32),
    Buffer.alloc(32),
    amountBytes,
    u8(0),
    u8(1),
    u32(5),
  ]);
};

const transactionAck = () =>
  Buffer.concat([Buffer.alloc(32), u8(1), u8(0)]);

type Send = (type: number, id: number | null, data: Buffer) => void;
type Handler = (type: number, id: number | null, send: Send) => void;

// A minimal TLS websocket server that speaks just enough of the Chia protocol for these tests.
async function mockFullNode(handler: Handler) {
  const cert = Certificate.generate();
  const server: Server = createServer({ cert: cert.certPem, key: cert.keyPem });
  const sockets: Duplex[] = [];

  server.on("upgrade", (req, socket: Duplex) => {
    sockets.push(socket);

    const accept = createHash("sha1")
      .update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );

    const send: Send = (type, id, data) => {
      if (!socket.destroyed) {
        socket.write(encodeFrame(2, encodeMessage(type, id, data)));
      }
    };

    let buffer = Buffer.alloc(0);

    socket.on("error", () => {});
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);

      while (buffer.length >= 2) {
        const opcode = buffer[0] & 0x0f;
        let length = buffer[1] & 0x7f;
        let offset = 2;

        if (length === 126) {
          if (buffer.length < 4) return;
          length = buffer.readUInt16BE(2);
          offset = 4;
        } else if (length === 127) {
          if (buffer.length < 10) return;
          length = Number(buffer.readBigUInt64BE(2));
          offset = 10;
        }

        // Frames from the client are always masked.
        if (buffer.length < offset + 4 + length) return;
        const mask = buffer.subarray(offset, offset + 4);
        const payload = Buffer.from(buffer.subarray(offset + 4, offset + 4 + length));
        for (let i = 0; i < payload.length; i++) {
          payload[i] ^= mask[i % 4];
        }
        buffer = buffer.subarray(offset + 4 + length);

        if (opcode === 8) {
          socket.end(encodeFrame(8, payload));
          return;
        }

        if (opcode === 9) {
          socket.write(encodeFrame(10, payload));
          continue;
        }

        if (opcode !== 2) continue;

        const message = decodeMessage(payload);

        if (message.type === HANDSHAKE) {
          send(HANDSHAKE, null, handshake());
          continue;
        }

        handler(message.type, message.id, send);
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    addr: `127.0.0.1:${port}`,
    close: () => {
      for (const socket of sockets) {
        socket.destroy();
      }
      server.close();
    },
  };
}

async function connect(addr: string, options = new PeerOptions()) {
  const connector = new Connector(Certificate.generate());
  return Peer.connect(NETWORK_ID, addr, connector, options);
}

test("peer options default to a 60 second request timeout", (t) => {
  const options = new PeerOptions();
  t.is(options.requestTimeoutMs, 60_000);

  options.requestTimeoutMs = null;
  t.is(options.requestTimeoutMs, null);
});

test("peer requests children and sends transactions", async (t) => {
  const node = await mockFullNode((type, id, send) => {
    if (type === REQUEST_CHILDREN) send(RESPOND_CHILDREN, id, respondChildren(42));
    if (type === SEND_TRANSACTION) send(TRANSACTION_ACK, id, transactionAck());
  });

  try {
    const peer = await connect(node.addr);

    const children = await peer.requestChildren(Buffer.alloc(32));
    t.is(children.length, 1);
    t.is(children[0].coin.amount, 42n);
    t.is(children[0].createdHeight, 5);
    t.is(children[0].spentHeight, null);

    const ack = await peer.sendTransaction(
      new SpendBundle([], Signature.infinity()),
    );
    t.is(ack.status, 1);
    t.is(ack.error, null);

    await peer.close();
  } finally {
    node.close();
  }
});

test("peer requests time out", async (t) => {
  const node = await mockFullNode(() => {});

  try {
    const options = new PeerOptions();
    options.requestTimeoutMs = 200;
    const peer = await connect(node.addr, options);

    await t.throwsAsync(peer.requestChildren(Buffer.alloc(32)), {
      message: /Timed out/,
    });
  } finally {
    node.close();
  }
});

test("undrained events don't block responses", async (t) => {
  const node = await mockFullNode((type, id, send) => {
    if (type !== REQUEST_CHILDREN) return;
    for (let height = 0; height < 100; height++) {
      send(NEW_PEAK_WALLET, null, newPeakWallet(height));
    }
    send(RESPOND_CHILDREN, id, respondChildren(1));
  });

  try {
    const options = new PeerOptions();
    options.requestTimeoutMs = 10_000;
    const peer = await connect(node.addr, options);

    const children = await peer.requestChildren(Buffer.alloc(32));
    t.is(children.length, 1);

    const event = await peer.next();
    t.is(event?.newPeakWallet?.height, 0);
  } finally {
    node.close();
  }
});

test("close ends the event stream", async (t) => {
  const node = await mockFullNode(() => {});

  try {
    const peer = await connect(node.addr);
    await peer.close();

    t.is(await peer.next(), null);
    await t.throwsAsync(peer.requestChildren(Buffer.alloc(32)), {
      message: /closed/,
    });
  } finally {
    node.close();
  }
});
