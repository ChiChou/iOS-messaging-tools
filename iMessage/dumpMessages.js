// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


// Returns a string representation of an objC object.
function po(p) {
    return ObjC.Object(p).toString();
}

const COMPRESSION_ZLIB = 0x205;
const SCRATCH_SIZE = 0x20090; // zlib_decode_scratch_size
const compression_decode_buffer_addr = Module.getExportByName(null, "compression_decode_buffer");
const compression_decode_buffer = new NativeFunction(compression_decode_buffer_addr, 'ulong', ['pointer', 'ulong', 'pointer', 'ulong', 'pointer', 'int']);

function isGZip(data) {
    const u16 = new Uint16Array(1);
    u16[0] = data.bytes().readU16();
    const bytes = new Uint8Array(u16.buffer);
    return bytes[0] == 0x1f && bytes[1] == 0x8b;
}

// Parses an iMessage and returns a string representation of it.
function pm(p) {
    if (p.isNull()) {
        return "";
    }

    // Content is a NSData instance
    var content = ObjC.Object(p);
    if (isGZip(content)) {
        const bytes = content.bytes();
        const output = Memory.alloc(SCRATCH_SIZE);
        const outSize = compression_decode_buffer(output, SCRATCH_SIZE, bytes.add(10), bytes.length - 10, NULL, COMPRESSION_ZLIB);
        content = ObjC.classes.NSData.dataWithBytes_length_(output, outSize);
    }

    var pList = ObjC.classes.NSPropertyListSerialization.propertyListWithData_options_format_error_(content, 0, ObjC.Object(NULL), ObjC.Object(NULL));
    if (pList == null) {
        return content.toString();
    } else {
        return pList.toString();
    }
}

const selector = '- handler:incomingMessage:originalEncryptionType:messageID:toIdentifier:' + 
    'fromIdentifier:fromToken:timeStamp:fromIDSID:incomingEngroup:needsDeliveryReceipt:' +
    'deliveryContext:storageContext:messageContext:isBeingReplayed:mergeID:';
const messageHandlerAddr = ObjC.classes.MessageServiceSession[selector].implementation;

send("Hooking -[MessageServiceSession handler:incomingMessage:...] @ " + messageHandlerAddr);
Interceptor.attach(messageHandlerAddr, {
    onEnter: function(args) {
        send({message: pm(args[3]), messageID: po(args[5]), toIdentifier: po(args[6]), fromIdentifier: po(args[7])});
    }
});
