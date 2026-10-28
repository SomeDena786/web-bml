// STD-B24 第四編 第5章 セクション形式のアプリケーション制御情報 (AIT table_id=0x74)
import type { TSPacket } from "arib-mmt-tlv-ts/ts/packet.js";

export type AITTransportProtocol = {
    protocolId: number,
    transportProtocolLabel: number,
    // protocol_id=0x0003 (HTTP/HTTPS)
    urls?: { urlBase: string, urlExtensions: string[] }[],
    // protocol_id=0x0004 (データカルーセル)
    carousel?: { originalNetworkId?: number, transportStreamId?: number, serviceId?: number, componentTag: number },
};

export type AITBoundaryAndPermission = {
    permissionBitmaps: number[],
    managedURLs: string[],
};

export type AITApplication = {
    organizationId: number,
    applicationId: number,
    controlCode: number,
    profiles: { profile: number, major: number, minor: number, micro: number }[],
    serviceBound: boolean,
    visibility: number,
    priority: number,
    transportProtocolLabels: number[],
    transports: AITTransportProtocol[],
    location?: string,
    boundaries: AITBoundaryAndPermission[],
    autostartPriority?: number,
};

export type AITSection = {
    applicationType: number,
    version: number,
    sectionNumber: number,
    lastSectionNumber: number,
    commonTransports: AITTransportProtocol[],
    applications: AITApplication[],
};

const latin1 = new TextDecoder("latin1");

function readTransportProtocol(d: Uint8Array): AITTransportProtocol | undefined {
    if (d.length < 3) {
        return undefined;
    }
    const protocolId = (d[0] << 8) | d[1];
    const transportProtocolLabel = d[2];
    const result: AITTransportProtocol = { protocolId, transportProtocolLabel };
    let off = 3;
    if (protocolId === 0x0003) {
        result.urls = [];
        while (off < d.length) {
            const baseLength = d[off++];
            const urlBase = latin1.decode(d.subarray(off, off + baseLength));
            off += baseLength;
            const extCount = d[off++] ?? 0;
            const urlExtensions: string[] = [];
            for (let i = 0; i < extCount && off < d.length; i++) {
                const extLength = d[off++];
                urlExtensions.push(latin1.decode(d.subarray(off, off + extLength)));
                off += extLength;
            }
            result.urls.push({ urlBase, urlExtensions });
        }
    } else if (protocolId === 0x0004 && d.length >= 4) {
        const remote = !!(d[off] & 0x80);
        off++;
        if (remote && d.length >= off + 7) {
            result.carousel = {
                originalNetworkId: (d[off] << 8) | d[off + 1],
                transportStreamId: (d[off + 2] << 8) | d[off + 3],
                serviceId: (d[off + 4] << 8) | d[off + 5],
                componentTag: d[off + 6],
            };
        } else if (d.length > off) {
            result.carousel = { componentTag: d[off] };
        }
    }
    return result;
}

function readBoundaries(d: Uint8Array): AITBoundaryAndPermission[] {
    // STD-B24 第四編 5.3.4 アプリケーション境界権限設定記述子
    const result: AITBoundaryAndPermission[] = [];
    let off = 0;
    while (off < d.length) {
        const b: AITBoundaryAndPermission = { permissionBitmaps: [], managedURLs: [] };
        const bitmapCount = d[off++];
        for (let i = 0; i < bitmapCount && off + 1 < d.length; i++) {
            b.permissionBitmaps.push((d[off] << 8) | d[off + 1]);
            off += 2;
        }
        const urlCount = d[off++] ?? 0;
        for (let i = 0; i < urlCount && off < d.length; i++) {
            const len = d[off++];
            b.managedURLs.push(latin1.decode(d.subarray(off, off + len)));
            off += len;
        }
        result.push(b);
    }
    return result;
}

function* descriptors(d: Uint8Array): Generator<[number, Uint8Array]> {
    let off = 0;
    while (off + 2 <= d.length) {
        const tag = d[off];
        const len = d[off + 1];
        yield [tag, d.subarray(off + 2, off + 2 + len)];
        off += 2 + len;
    }
}

export function parseAITSection(s: Uint8Array): AITSection | undefined {
    if (s.length < 12 || s[0] !== 0x74) {
        return undefined;
    }
    const sectionLength = ((s[1] & 0x0f) << 8) | s[2];
    const end = 3 + sectionLength - 4;
    if (end > s.length) {
        return undefined;
    }
    const applicationType = (s[3] << 8) | s[4];
    const version = (s[5] >> 1) & 0x1f;
    const currentNext = s[5] & 1;
    if (!currentNext) {
        return undefined;
    }
    const sectionNumber = s[6];
    const lastSectionNumber = s[7];
    let off = 8;
    const commonLength = ((s[off] & 0x0f) << 8) | s[off + 1];
    off += 2;
    const commonTransports: AITTransportProtocol[] = [];
    for (const [tag, d] of descriptors(s.subarray(off, off + commonLength))) {
        if (tag === 0x02) {
            const t = readTransportProtocol(d);
            if (t != null) {
                commonTransports.push(t);
            }
        }
    }
    off += commonLength;
    const loopLength = ((s[off] & 0x0f) << 8) | s[off + 1];
    off += 2;
    const loopEnd = Math.min(off + loopLength, end);
    const applications: AITApplication[] = [];
    while (off + 9 <= loopEnd) {
        const organizationId = (s[off] << 8) | s[off + 1];
        const applicationId = ((s[off + 2] << 24) | (s[off + 3] << 16) | (s[off + 4] << 8) | s[off + 5]) >>> 0;
        const controlCode = s[off + 6];
        const descLength = ((s[off + 7] & 0x0f) << 8) | s[off + 8];
        off += 9;
        const app: AITApplication = {
            organizationId,
            applicationId,
            controlCode,
            profiles: [],
            serviceBound: true,
            visibility: 3,
            priority: 0,
            transportProtocolLabels: [],
            transports: [],
            boundaries: [],
        };
        for (const [tag, d] of descriptors(s.subarray(off, off + descLength))) {
            if (tag === 0x00 && d.length >= 1) {
                // application_descriptor
                const profilesLength = d[0];
                let p = 1;
                while (p + 5 <= 1 + profilesLength) {
                    app.profiles.push({ profile: (d[p] << 8) | d[p + 1], major: d[p + 2], minor: d[p + 3], micro: d[p + 4] });
                    p += 5;
                }
                p = 1 + profilesLength;
                if (p + 2 <= d.length) {
                    app.serviceBound = !!(d[p] & 0x80);
                    app.visibility = (d[p] >> 5) & 3;
                    app.priority = d[p + 1];
                    app.transportProtocolLabels = [...d.subarray(p + 2)];
                }
            } else if (tag === 0x02) {
                const t = readTransportProtocol(d);
                if (t != null) {
                    app.transports.push(t);
                }
            } else if (tag === 0x15) {
                app.location = latin1.decode(d);
            } else if (tag === 0x30) {
                app.boundaries.push(...readBoundaries(d));
            } else if (tag === 0x31 && d.length >= 1) {
                // autostart_priority_descriptor
                app.autostartPriority = d[0];
            }
        }
        off += descLength;
        applications.push(app);
    }
    return { applicationType, version, sectionNumber, lastSectionNumber, commonTransports, applications };
}

/**
 * 指定PIDのTSパケットからセクションを組み立てる
 */
export class SectionAssembler {
    private buffer: Uint8Array | undefined;
    private filled = 0;
    private lastCC = -1;
    constructor(private readonly onSection: (section: Uint8Array) => void) { }

    public push(packet: TSPacket) {
        if (packet.adaptationFieldControl === 0 || packet.adaptationFieldControl === 2) {
            return;
        }
        if (this.lastCC !== -1 && ((this.lastCC + 1) & 15) !== packet.continuityCounter) {
            this.buffer = undefined;
        }
        this.lastCC = packet.continuityCounter;
        let payload = packet.data.subarray(packet.payloadOffset);
        if (packet.payloadUnitStartIndicator) {
            const pointer = payload[0];
            const head = payload.subarray(1, 1 + pointer);
            if (this.buffer != null) {
                this.append(head);
            }
            this.buffer = undefined;
            payload = payload.subarray(1 + pointer);
            this.startSections(payload);
        } else if (this.buffer != null) {
            this.append(payload);
        }
    }

    private startSections(payload: Uint8Array) {
        while (payload.length >= 3 && payload[0] !== 0xff) {
            const length = 3 + (((payload[1] & 0x0f) << 8) | payload[2]);
            this.buffer = new Uint8Array(length);
            this.filled = 0;
            const n = Math.min(length, payload.length);
            this.append(payload.subarray(0, n));
            payload = payload.subarray(n);
        }
    }

    private append(data: Uint8Array) {
        if (this.buffer == null) {
            return;
        }
        const n = Math.min(this.buffer.length - this.filled, data.length);
        this.buffer.set(data.subarray(0, n), this.filled);
        this.filled += n;
        if (this.filled === this.buffer.length) {
            const section = this.buffer;
            this.buffer = undefined;
            this.onSection(section);
        }
    }
}
